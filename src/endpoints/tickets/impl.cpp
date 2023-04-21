#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/ticket_administration.hpp>

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

namespace adm = irods::experimental::administration;
namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

namespace
{
    // clang-format off
    using query_arguments_type = decltype(irods::http::url::query);
    using handler_type         = irods::http::response_type(*)(const irods::http::request_type& _req, const query_arguments_type& _args);
    // clang-format on

    //
    // Handler function prototypes
    //

    auto handle_list_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_create_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"list", handle_list_op},
        {"stat", handle_stat_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"create", handle_create_op},
        {"remove", handle_remove_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /tickets.
    auto tickets(const request_type& _req) -> response_type
    {
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
        else if (_req.method() == verb_type::post) {
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
    } // tickets
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_list_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
#if 0
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
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
#endif
    } // handle_list_op

    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
#if 0
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
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
#endif
    } // handle_stat_op

    auto handle_create_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto ticket_type = adm::ticket::ticket_type::read;
            const auto type_iter = _args.find("type");
            if (type_iter != std::end(_args)) {
                if (type_iter->second == "write") {
                    ticket_type = adm::ticket::ticket_type::write;
                }
                else if (type_iter->second != "read") {
                    log::error("{}: Missing [type] parameter.", __func__);
                    return irods::http::fail(res, http::status::bad_request);
                }
            }

            irods::experimental::client_connection conn;
            const auto ticket = adm::ticket::client::create_ticket(conn, ticket_type, lpath_iter->second);

            auto constraint_iter = _args.find("use-count");
            if (constraint_iter != std::end(_args)) {
                const auto count = std::stoi(constraint_iter->second);
                adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::use_count_constraint{count});
            }
            else {
                adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::use_count_constraint{0});
            }

            constraint_iter = _args.find("write-data-object-count");
            if (constraint_iter != std::end(_args)) {
                const auto count = std::stoi(constraint_iter->second);
                adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::n_writes_to_data_object_constraint{count});
            }
            else {
                adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::n_writes_to_data_object_constraint{0});
            }

            constraint_iter = _args.find("write-byte-count");
            if (constraint_iter != std::end(_args)) {
                const auto count = std::stoi(constraint_iter->second);
                adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::n_write_bytes_constraint{count});
            }
            else {
                adm::ticket::client::set_ticket_constraint(conn, ticket, adm::ticket::n_write_bytes_constraint{0});
            }

            constraint_iter = _args.find("seconds-until-expiration");
            if (constraint_iter != std::end(_args)) {
                // TODO Not yet supported by the ticket administration library.
                log::warn("{}: Ignoring [seconds-until-expiration]. Not implemented at this time.", __func__);
            }

            constraint_iter = _args.find("users");
            if (constraint_iter != std::end(_args)) {
                std::vector<std::string> users;
                boost::split(users, constraint_iter->second, boost::is_any_of(","));
                for (const auto& user : users) {
                    adm::ticket::client::add_ticket_constraint(conn, ticket, adm::ticket::user_constraint{user});
                }
            }

            constraint_iter = _args.find("groups");
            if (constraint_iter != std::end(_args)) {
                std::vector<std::string> groups;
                boost::split(groups, constraint_iter->second, boost::is_any_of(","));
                for (const auto& group : groups) {
                    adm::ticket::client::add_ticket_constraint(conn, ticket, adm::ticket::group_constraint{group});
                }
            }

            constraint_iter = _args.find("hosts");
            if (constraint_iter != std::end(_args)) {
                std::vector<std::string> hosts;
                boost::split(hosts, constraint_iter->second, boost::is_any_of(","));
                for (const auto& host : hosts) {
                    adm::ticket::client::add_ticket_constraint(conn, ticket, adm::ticket::host_constraint{host});
                }
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"ticket", ticket}
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
    } // handle_create_op

    auto handle_remove_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            irods::experimental::client_connection conn;
            adm::ticket::client::delete_ticket(conn, name_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
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
    } // handle_remove_op
} // anonymous namespace
