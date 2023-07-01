#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/atomic_apply_metadata_operations.h>
#include <irods/client_connection.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/asio.hpp>
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
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

namespace
{
    using handler_type = void(*)(irods::http::session_pointer_type&, irods::http::request_type&, irods::http::query_arguments_type&);

    //
    // Handler function prototypes
    //

    auto handle_execute_op(irods::http::session_pointer_type& _sess_ptr,
                           irods::http::request_type& _req,
                           irods::http::query_arguments_type& _args) -> void;

    //
    // Operation to Handler mappings
    //

#if 0
    const std::unordered_map<std::string, handler_type> handlers_for_get{
    };
#endif

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"execute", handle_execute_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(metadata)
    {
#if 0
        if (_req.method() == verb_type::get) {
            auto url = irods::http::parse_url(_req);

            const auto op_iter = url.query.find("op");
            if (op_iter == std::end(url.query)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return irods::http::fail(status_type::bad_request);
            }

            if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
                return (iter->second)(_sess_ptr, _req, url.query);
            }

            return _sess_ptr->send(fail(status_type::bad_request));
        }
        else
#endif
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
    } // metadata
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_execute_op(irods::http::session_pointer_type& _sess_ptr,
                                  irods::http::request_type& _req,
                                  irods::http::query_arguments_type& _args) -> void
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        const auto data_iter = _args.find("json");
        if (data_iter == std::end(_args)) {
            log::error("{}: Missing [data] parameter.", __func__);
            return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
        }

        log::trace("{}: Scheduling atomic metadata operations on long-running task thread pool.", __func__);

        net::post(*irods::http::globals::thread_pool_bg, [fn = __func__, _sess_ptr, client_info, res = std::move(res), json_input = data_iter->second]() mutable {
            try {
                log::trace("{}: Executing metadata operations.", fn);

                char* output{};
                irods::at_scope_exit_unsafe free_output{[&output] { std::free(output); }};

                auto conn = irods::get_connection(client_info->username);
                const auto ec = rc_atomic_apply_metadata_operations(static_cast<RcComm*>(conn), json_input.c_str(), &output);

                if (ec != 0) {
                    res.result(http::status::bad_request);
                }

                json error_info;
                if (output) {
                    error_info = json::parse(output);
                }

                res.body() = json{
                    {"irods_response", {
                        {"error_code", ec}
                    }},
                    {"error_info", error_info}
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

            log::trace("{}: Metadata operations complete. Sending response.", fn);
            return _sess_ptr->send(std::move(res));
        });
    } // handle_execute_op
} // anonymous namespace
