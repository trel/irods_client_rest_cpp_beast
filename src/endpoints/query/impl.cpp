#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/procApiRequest.h>
#include <irods/query_builder.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/algorithm/string.hpp>
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
    using handler_type         = void(*)(irods::http::session_pointer_type, const irods::http::request_type&, const query_arguments_type&);
    // clang-format on

    //
    // Handler function prototypes
    //

    auto handle_execute_genquery_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void;
    auto handle_execute_specific_query_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void;
    auto handle_list_genquery_columns_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void;
    auto handle_list_specific_queries_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void;
    auto handle_add_specific_query_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void;
    auto handle_remove_specific_query_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"execute_genquery", handle_execute_genquery_op},
        {"execute_specific_query", handle_execute_specific_query_op},
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
                return (iter->second)(_sess_ptr, _req, url.query);
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
                return (iter->second)(_sess_ptr, _req, args);
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

    auto handle_execute_genquery_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        const auto query_iter = _args.find("query");
        if (query_iter == std::end(_args)) {
            log::error("{}: Missing [query] parameter.", __func__);
            return _sess_ptr->send(irods::http::fail(http::status::bad_request));
        }

        const auto parser_iter = _args.find("parser");
        if (parser_iter != std::end(_args)) {
            if (parser_iter->second != "genquery1" || parser_iter->second != "genquery2") {
                log::error("{}: Missing [parser] parameter.", __func__);
                return _sess_ptr->send(irods::http::fail(http::status::bad_request));
            }
        }

        const auto to_int = [fn = __func__](const std::string& _v) {
            try {
                return std::stoi(_v);
            }
            catch (const std::exception& e) {
                log::error("{}: Error: {}", fn, e.what());
                return -1;
            }
        };

        int offset = 0;
        if (const auto iter = _args.find("offset"); iter != std::end(_args)) {
            offset = to_int(iter->second);
        }

        int count = 32; // TODO Configurable?
        if (const auto iter = _args.find("count"); iter != std::end(_args)) {
            count = to_int(iter->second);
        }
        count = std::clamp(count, 1, 32);

        // TODO GenQuery2 is definitely the right answer for this simply because of
        // pagination features such as OFFSET and LIMIT. We can make that a runtime
        // configuration option.

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        net::post(*irods::http::globals::thread_pool_bg, [_sess_ptr, client_info, parser = parser_iter->second, gql = query_iter->second, res = std::move(res), offset, count]() mutable {
            try {
                json::array_t row;
                json::array_t rows;

                {
                    auto conn = irods::get_connection(client_info->username);

                    if ("genquery2" == parser) {
                        char* sql{};

                        const auto ec = procApiRequest(static_cast<RcComm*>(conn),
                                                       1'000'001, // TODO GenQuery2 API number. Need a better way to get this.
                                                       gql.c_str(),
                                                       nullptr,
                                                       reinterpret_cast<void**>(&sql),
                                                       nullptr);

                        if (ec < 0) {
                            res.result(http::status::bad_request);
                            res.body() = json{
                                {"irods_response", {
                                    {"error_code", ec},
                                }}
                            }.dump();
                        }
                        
                        // The string below contains a format placeholder for the "rows" property
                        // because this avoids the need to parse the GenQuery2 results into an nlohmann
                        // JSON object just to serialize it for the response.
                        constexpr const auto* json_fmt_string = R"_({{"irods_response": {{"error_code": 0}}, {{"rows": {}}}}})_";
                        res.body() = fmt::format(json_fmt_string, sql);
                    }
                    else {
                        int offset_counter = 0;
                        int count_counter = 0;

                        for (auto&& r : irods::query{static_cast<RcComm*>(conn), gql}) {
                            if (offset_counter < offset) {
                                ++offset_counter;
                                continue;
                            }

                            for (auto&& c : r) {
                                row.push_back(c);
                            }

                            rows.push_back(row);
                            row.clear();

                            if (++count_counter == count) {
                                break;
                            }
                        }

                        res.body() = json{
                            {"irods_response", {
                                {"error_code", 0},
                            }},
                            {"rows", rows}
                        }.dump();
                    }
                }
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_execute_genquery_op

    auto handle_execute_specific_query_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        const auto name_iter = _args.find("name");
        if (name_iter == std::end(_args)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return _sess_ptr->send(irods::http::fail(http::status::bad_request));
        }

        const auto to_int = [fn = __func__](const std::string& _v) {
            try {
                return std::stoi(_v);
            }
            catch (const std::exception& e) {
                log::error("{}: Error: {}", fn, e.what());
                return -1;
            }
        };

        int offset = 0;
        if (const auto iter = _args.find("offset"); iter != std::end(_args)) {
            offset = to_int(iter->second);
        }

        int count = 32; // TODO Configurable?
        if (const auto iter = _args.find("count"); iter != std::end(_args)) {
            count = to_int(iter->second);
        }
        count = std::clamp(count, 1, 32);

        std::vector<std::string> args;

        if (const auto iter = _args.find("args"); iter != std::end(_args) && !iter->second.empty()) {
            boost::split(args, iter->second, boost::is_any_of(","));
        }

        // TODO GenQuery2 is definitely the right answer for this simply because of
        // pagination features such as OFFSET and LIMIT. We can make that a runtime
        // configuration option.

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        net::post(*irods::http::globals::thread_pool_bg, [_sess_ptr, client_info, name = name_iter->second, res = std::move(res), offset, count, args = std::move(args)]() mutable {
            try {
                json::array_t row;
                json::array_t rows;

                {
                    irods::experimental::query_builder qb;

                    qb.type(irods::experimental::query_type::specific);
                    qb.bind_arguments(args);
                    //qb.row_offset(offset);
                    //qb.row_limit(count);
                    //qb.zone_hint("");

                    int offset_counter = 0;
                    int count_counter = 0;

                    auto conn = irods::get_connection(client_info->username);

                    for (auto&& r : qb.build<RcComm>(conn, name)) {
                        if (offset_counter < offset) {
                            ++offset_counter;
                            continue;
                        }

                        for (auto&& c : r) {
                            row.push_back(c);
                        }

                        rows.push_back(row);
                        row.clear();

                        if (++count_counter == count) {
                            break;
                        }
                    }
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_execute_genquery_op

    auto handle_list_genquery_columns_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
    } // handle_list_genquery_columns_op

    auto handle_list_specific_queries_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
    } // handle_list_specific_queries_op

    auto handle_add_specific_query_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
    } // handle_add_specific_query_op

    auto handle_remove_specific_query_op(irods::http::session_pointer_type _sess_ptr, const irods::http::request_type& _req, const query_arguments_type& _args) -> void
    {
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
    } // handle_remove_specific_query_op
} // anonymous namespace
