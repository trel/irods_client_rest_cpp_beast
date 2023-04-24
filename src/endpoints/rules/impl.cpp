#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/client_connection.hpp>
#include <irods/execCmd.h>
#include <irods/execMyRule.h>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/msParam.h>
#include <irods/rcMisc.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/ruleExecDel.h>

#include <boost/asio.hpp>
//#include <boost/asio/ip/tcp.hpp> // TODO Remove
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
//namespace net   = boost::asio;      // from <boost/asio.hpp>

//using tcp = boost::asio::ip::tcp;   // from <boost/asio/ip/tcp.hpp> // TODO Remove

namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

namespace
{
    // clang-format off
    using query_arguments_type = decltype(irods::http::url::query); // TODO Could be moved to common.hpp
    using handler_type         = irods::http::response_type(*)(const irods::http::request_type& _req, const query_arguments_type& _args);
    // clang-format on

    //
    // Handler function prototypes
    //

    auto handle_execute_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_delay_rule_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_modify_delay_rule_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_list_rule_engines_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_list_delay_rules_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"list_rule_engines", handle_list_rule_engines_op},
        {"list_delay_rules", handle_list_delay_rules_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"execute", handle_execute_op},
        {"remove_delay_rule", handle_remove_delay_rule_op},
        {"modify_delay_rule", handle_modify_delay_rule_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /rules.
    auto rules(session_pointer_type _sess_ptr, const request_type& _req) -> void
    {
        if (_req.method() == verb_type::get) {
            const auto url = irods::http::parse_url(_req);

            const auto op_iter = url.query.find("op");
            if (op_iter == std::end(url.query)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return _sess_ptr->send(irods::http::fail(status_type::bad_request));
            }

            if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
                return _sess_ptr->send((iter->second)(_req, url.query));
            }
        }
        else if (_req.method() == verb_type::post) {
            const auto args = irods::http::to_argument_list(_req.body());

            const auto op_iter = args.find("op");
            if (op_iter == std::end(args)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return _sess_ptr->send(irods::http::fail(status_type::bad_request));
            }

            if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
                return _sess_ptr->send((iter->second)(_req, args));
            }
        }

        log::error("{}: Incorrect HTTP method.", __func__);
        return _sess_ptr->send(irods::http::fail(status_type::method_not_allowed));
    } // rules
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_execute_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto rule_text_iter = _args.find("rule-text");
            if (rule_text_iter == std::end(_args)) {
                log::error("{}: Missing [rule-text] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            ExecMyRuleInp input{};

            irods::at_scope_exit clear_kvp{[&input] {
                clearKeyVal(&input.condInput);
                clearMsParamArray(input.inpParamArray, 0); // 0 -> do not free external structure.
            }};

            const auto rule_text = fmt::format("@external rule {{ {} }}", rule_text_iter->second);
            std::strncpy(input.myRule, rule_text.c_str(), sizeof(ExecMyRuleInp::myRule));

            const auto rep_instance_iter = _args.find("rep-instance");
            if (rep_instance_iter != std::end(_args)) {
                addKeyVal(&input.condInput, irods::KW_CFG_INSTANCE_NAME, rep_instance_iter->second.c_str());
            }

            MsParamArray param_array{};
            input.inpParamArray = &param_array; // TODO Need to accept INPUT params.
            std::strncpy(input.outParamDesc, "ruleExecOut", sizeof(input.outParamDesc)); // TODO Need to accept OUTPUT params.

            MsParamArray* out_param_array{};

            json stdout_output;
            json stderr_output;

            auto conn = irods::get_connection(client_info->username);
            const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array);

            if (ec >= 0) {
                if (auto* msp = getMsParamByType(out_param_array, ExecCmdOut_MS_T); msp) {
                    if (const auto* exec_out = static_cast<ExecCmdOut*>(msp->inOutStruct); exec_out) {
                        if (exec_out->stdoutBuf.buf) {
                            stdout_output = static_cast<const char*>(exec_out->stdoutBuf.buf);
                            log::debug("{}: stdout_output = [{}]", __func__, stdout_output.get_ref<const std::string&>());
                        }

                        if (exec_out->stderrBuf.buf) {
                            stderr_output = static_cast<const char*>(exec_out->stderrBuf.buf);
                            log::debug("{}: stderr_output = [{}]", __func__, stderr_output.get_ref<const std::string&>());
                        }
                    }
                }

                if (auto* msp = getMsParamByLabel(out_param_array, "ruleExecOut"); msp) {
                    log::debug("{}: ruleExecOut = [{}]", __func__, (char*) msp->inOutStruct);
                }
            }

            // TODO Probably not needed.
            //printErrorStack(static_cast<RcComm*>(conn)->rError);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
                {"stdout", stdout_output},
                {"stderr", stderr_output}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_execute_op

    auto handle_remove_delay_rule_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto rule_id_iter = _args.find("rule-id");
            if (rule_id_iter == std::end(_args)) {
                log::error("{}: Missing [rule-id] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            RuleExecDeleteInput input{};
            std::strncpy(input.ruleExecId, rule_id_iter->second.c_str(), sizeof(RuleExecDeleteInput::ruleExecId));

            auto conn = irods::get_connection(client_info->username);
            const auto ec = rcRuleExecDel(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_remove_delay_rule_op

    auto handle_modify_delay_rule_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    } // handle_modify_delay_rule_op

    auto handle_list_rule_engines_op(const irods::http::request_type& _req, const query_arguments_type&) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            ExecMyRuleInp input{};

            irods::at_scope_exit clear_kvp{[&input] {
                clearKeyVal(&input.condInput);
                clearMsParamArray(input.inpParamArray, 0); // 0 -> do not free external structure.
            }};

            addKeyVal(&input.condInput, AVAILABLE_KW, "");

            MsParamArray param_array{};
            input.inpParamArray = &param_array;

            MsParamArray* out_param_array{};

            auto conn = irods::get_connection(client_info->username);
            const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array);

            std::vector<std::string> plugin_instances;

            if (ec >= 0) {
                if (const auto* es = static_cast<RcComm*>(conn)->rError; es && es->len > 0) {
                    boost::split(plugin_instances, es->errMsg[0]->msg, boost::is_any_of("\n"));
                }

                plugin_instances.erase(std::begin(plugin_instances)); // Remove unnecessary header.
                plugin_instances.pop_back(); // Remove empty line as a result of splitting the string via a newline.

                // Remove leading and trailing whitespace.
                std::for_each(std::begin(plugin_instances), std::end(plugin_instances), [](auto& _v) { boost::trim(_v); });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
                {"rule_engine_plugin_instances", plugin_instances},
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_list_rule_engines_op

    auto handle_list_delay_rules_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            // TODO
            const auto all_rules_iter = _args.find("all-rules");
            if (all_rules_iter != std::end(_args)) {
            }

            const auto gql = fmt::format(
                "select "
                "RULE_EXEC_ID, "
                "RULE_EXEC_NAME, "
                "RULE_EXEC_REI_FILE_PATH, "
                "RULE_EXEC_USER_NAME, "
                "RULE_EXEC_ADDRESS, "
                "RULE_EXEC_TIME, "
                "RULE_EXEC_FREQUENCY, "
                "RULE_EXEC_PRIORITY, "
                "RULE_EXEC_ESTIMATED_EXE_TIME, "
                "RULE_EXEC_NOTIFICATION_ADDR, "
                "RULE_EXEC_LAST_EXE_TIME, "
                "RULE_EXEC_STATUS, "
#if 0
                "RULE_EXEC_CONTEXT "
                "where RULE_EXEC_USER_NAME = '{}'",
                *username);
#else
                "RULE_EXEC_CONTEXT");
#endif

            json::array_t row;
            json::array_t rows;

            auto conn = irods::get_connection(client_info->username);

            for (auto&& r : irods::query{static_cast<RcComm*>(conn), gql}) {
                for (auto&& c : r) {
                    row.push_back(c);
                }

                rows.push_back(row);
                row.clear();
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"rows", rows}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_list_delay_rules_op
} // anonymous namespace
