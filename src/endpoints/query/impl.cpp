#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
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
    auto handle_list_genquery_columns_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_list_specific_queries_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_add_specific_query_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_specific_query_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"execute", handle_execute_op},
        {"list_genquery_columns", handle_list_genquery_columns_op},
        {"list_specific_queries", handle_list_specific_queries_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"add_specific_query", handle_add_specific_query_op},
        {"remove_specific_query", handle_remove_specific_query_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /query.
    auto query(session_pointer_type _sess_ptr, const request_type& _req) -> void
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

            return _sess_ptr->send(fail(status_type::bad_request));
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

            return _sess_ptr->send(fail(status_type::bad_request));
        }

        log::error("{}: Incorrect HTTP method.", __func__);
        return _sess_ptr->send(irods::http::fail(status_type::method_not_allowed));
    } // query
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
            const auto query_iter = _args.find("query");
            if (query_iter == std::end(_args)) {
                log::error("{}: Missing [query] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

#if 0
            const auto query_type_iter = _args.find("query-type");
            if (query_type_iter != std::end(_args)) {
                log::error("{}: Missing [query-type] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }
#endif
            // TODO GenQuery2 is definitely the right answer for this simply because of
            // pagination features such as OFFSET and LIMIT. We can make that a runtime
            // configuration option.

            json::array_t row;
            json::array_t rows;

            auto conn = irods::get_connection(client_info->username);

            for (auto&& r : irods::query{static_cast<RcComm*>(conn), query_iter->second}) {
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
    } // handle_execute_op

    auto handle_list_genquery_columns_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    } // handle_list_genquery_columns_op

    auto handle_list_specific_queries_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    } // handle_list_specific_queries_op

    auto handle_add_specific_query_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    } // handle_add_specific_query_op

    auto handle_remove_specific_query_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    } // handle_remove_specific_query_op
} // anonymous namespace
