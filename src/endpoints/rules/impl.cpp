#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/execCmd.h>
#include <irods/execMyRule.h>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/msParam.h>
#include <irods/rcMisc.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/ruleExecDel.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

#define IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(name) \
  auto name(                                              \
	  irods::http::session_pointer_type _sess_ptr,        \
	  irods::http::request_type& _req,                    \
	  irods::http::query_arguments_type& _args)           \
	  ->void

namespace
{
	using handler_type =
		void (*)(irods::http::session_pointer_type, irods::http::request_type&, irods::http::query_arguments_type&);

	//
	// Handler function prototypes
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_execute);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove_delay_rule);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list_rule_engines);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, handler_type> handlers_for_get{
		{"list_rule_engines", op_list_rule_engines}
	};

	const std::unordered_map<std::string, handler_type> handlers_for_post{
		{"execute", op_execute},
		{"remove_delay_rule", op_remove_delay_rule}
	};
	// clang-format on
} // anonymous namespace

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(rules)
	{
		if (_req.method() == verb_type::get) {
			auto url = irods::http::parse_url(_req);

			const auto op_iter = url.query.find("op");
			if (op_iter == std::end(url.query)) {
				log::error("{}: Missing [op] parameter.", __func__);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
				return (iter->second)(_sess_ptr, _req, url.query);
			}

			return _sess_ptr->send(fail(status_type::bad_request));
		}

		if (_req.method() == verb_type::post) {
			auto args = irods::http::to_argument_list(_req.body());

			const auto op_iter = args.find("op");
			if (op_iter == std::end(args)) {
				log::error("{}: Missing [op] parameter.", __func__);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
				return (iter->second)(_sess_ptr, _req, args);
			}

			return _sess_ptr->send(fail(status_type::bad_request));
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

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_execute)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task([fn = __func__,
		                                       client_info,
		                                       _sess_ptr,
		                                       _req = std::move(_req),
		                                       _args = std::move(_args)] {
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto rule_text_iter = _args.find("rule-text");
				if (rule_text_iter == std::end(_args)) {
					log::error("{}: Missing [rule-text] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				ExecMyRuleInp input{};

				irods::at_scope_exit clear_kvp{[&input] { clearKeyVal(&input.condInput); }};

				const auto rule_text = fmt::format("@external rule {{ {} }}", rule_text_iter->second);
				std::strncpy(input.myRule, rule_text.c_str(), sizeof(ExecMyRuleInp::myRule));

				const auto rep_instance_iter = _args.find("rep-instance");
				if (rep_instance_iter != std::end(_args)) {
					addKeyVal(&input.condInput, irods::KW_CFG_INSTANCE_NAME, rep_instance_iter->second.c_str());
				}

				MsParamArray param_array{};

				irods::at_scope_exit clear_ms_param_array{[&param_array] {
					constexpr auto free_inOutStruct = 0;
					clearMsParamArray(&param_array, free_inOutStruct);
				}};

				input.inpParamArray = &param_array;
				std::strncpy(input.outParamDesc, "ruleExecOut", sizeof(input.outParamDesc));

				MsParamArray* out_param_array{};

				irods::at_scope_exit clear_out_param_array{[&out_param_array] {
					constexpr auto free_inOutStruct = 1;
					clearMsParamArray(out_param_array, free_inOutStruct);
					std::free(out_param_array); // NOLINT(cppcoreguidelines-owning-memory, cppcoreguidelines-no-malloc)
				}};

				json stdout_output;
				json stderr_output;

				auto conn = irods::get_connection(client_info.username);
				const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array);

				if (ec >= 0) {
					if (auto* msp = getMsParamByType(out_param_array, ExecCmdOut_MS_T); msp) {
						if (auto* exec_out = static_cast<ExecCmdOut*>(msp->inOutStruct); exec_out) {
							if (exec_out->stdoutBuf.buf) {
								stdout_output = static_cast<const char*>(exec_out->stdoutBuf.buf);
								log::debug("{}: stdout_output = [{}]", fn, stdout_output.get_ref<const std::string&>());
							}

							if (exec_out->stderrBuf.buf) {
								stderr_output = static_cast<const char*>(exec_out->stderrBuf.buf);
								log::debug("{}: stderr_output = [{}]", fn, stderr_output.get_ref<const std::string&>());
							}
						}
					}

					if (auto* msp = getMsParamByLabel(out_param_array, "ruleExecOut"); msp) {
						log::debug("{}: ruleExecOut = [{}]", fn, static_cast<const char*>(msp->inOutStruct));
					}
				}

				// Log messages stored in the RcComm::rError object.
				if (auto* rerr_info = static_cast<RcComm*>(conn)->rError; rerr_info) {
					for (auto&& err : std::span(rerr_info->errMsg, rerr_info->len)) {
						log::info("{}: RcComm::rError info = [status=[{}], message=[{}]]", fn, err->status, err->msg);
					}

					freeRError(rerr_info);
				}

				res.body() =
					json{{"irods_response", {{"status_code", ec}}}, {"stdout", stdout_output}, {"stderr", stderr_output}}
						.dump();
			}
			catch (const irods::exception& e) {
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_execute

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove_delay_rule)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				log::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto rule_id_iter = _args.find("rule-id");
					if (rule_id_iter == std::end(_args)) {
						log::error("{}: Missing [rule-id] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					RuleExecDeleteInput input{};
					std::strncpy(
						input.ruleExecId, rule_id_iter->second.c_str(), sizeof(RuleExecDeleteInput::ruleExecId));

					auto conn = irods::get_connection(client_info.username);
					const auto ec = rcRuleExecDel(static_cast<RcComm*>(conn), &input);

					res.body() = json{
						{"irods_response",
				         {
							 {"status_code", ec},
						 }}}.dump();
				}
				catch (const irods::exception& e) {
					res.result(http::status::bad_request);
					res.body() =
						json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
							.dump();
				}
				catch (const std::exception& e) {
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_remove_delay_rule

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list_rule_engines)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task([fn = __func__,
		                                       client_info,
		                                       _sess_ptr,
		                                       _req = std::move(_req),
		                                       _args = std::move(_args)] {
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				ExecMyRuleInp input{};

				irods::at_scope_exit clear_kvp{[&input] { clearKeyVal(&input.condInput); }};

				addKeyVal(&input.condInput, AVAILABLE_KW, "");

				MsParamArray param_array{};

				irods::at_scope_exit clear_ms_param_array{[&param_array] {
					constexpr auto free_inOutStruct = 0;
					clearMsParamArray(&param_array, free_inOutStruct);
				}};

				input.inpParamArray = &param_array;

				MsParamArray* out_param_array{};

				irods::at_scope_exit clear_out_param_array{[&out_param_array] {
					constexpr auto free_inOutStruct = 1;
					clearMsParamArray(out_param_array, free_inOutStruct);
					std::free(out_param_array);
				}};

				auto conn = irods::get_connection(client_info.username);
				const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array);

				std::vector<std::string> plugin_instances;

				if (ec >= 0) {
					if (const auto* es = static_cast<RcComm*>(conn)->rError; es && es->len > 0) {
						boost::split(plugin_instances, es->errMsg[0]->msg, boost::is_any_of("\n"));
					}

					plugin_instances.erase(std::begin(plugin_instances)); // Remove unnecessary header.
					plugin_instances.pop_back(); // Remove empty line as a result of splitting the string via a newline.

					// Remove leading and trailing whitespace.
					std::for_each(
						std::begin(plugin_instances), std::end(plugin_instances), [](auto& _v) { boost::trim(_v); });
				}

				res.body() =
					json{{"irods_response", {{"status_code", ec}}}, {"rule_engine_plugin_instances", plugin_instances}}
						.dump();
			}
			catch (const irods::exception& e) {
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_list_rule_engines
} // anonymous namespace
