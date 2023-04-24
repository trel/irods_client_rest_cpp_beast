#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"

#include <irods/atomic_apply_metadata_operations.h>
#include <irods/client_connection.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>

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
namespace net   = boost::asio;      // from <boost/asio.hpp>

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

    auto handle_atomic_execute_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"atomic_execute", handle_atomic_execute_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /metadata.
    auto metadata(const request_type& _req) -> response_type
    {
#if 0
        if (_req.method() == verb_type::get) {
            const auto url = irods::http::parse_url(_req);

            const auto op_iter = url.query.find("op");
            if (op_iter == std::end(url.query)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return irods::http::fail(status_type::bad_request);
            }

            if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
                return (iter->second)(_req, url.query);
            }
        }
        else
#endif
        if (_req.method() == verb_type::post) {
            const auto args = irods::http::to_argument_list(_req.body());

            const auto op_iter = args.find("op");
            if (op_iter == std::end(args)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return irods::http::fail(status_type::bad_request);
            }

            if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
                return (iter->second)(_req, args);
            }
        }

        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(status_type::method_not_allowed);
    } // metadata
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_atomic_execute_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
            const auto data_iter = _args.find("data");
            if (data_iter == std::end(_args)) {
                log::error("{}: Missing [data] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            char* output{};
            irods::at_scope_exit_unsafe free_output{[&output] { std::free(output); }};

            auto conn = irods::get_connection(client_info->username);
            const auto ec = rc_atomic_apply_metadata_operations(static_cast<RcComm*>(conn), data_iter->second.c_str(), &output);

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

        return res;
    } // handle_atomic_execute_op
} // anonymous namespace
