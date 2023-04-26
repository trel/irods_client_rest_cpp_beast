#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/user_administration.hpp>

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

    auto handle_create_user_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_user_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_set_password_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_set_user_type_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_add_user_auth_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_user_auth_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    auto handle_create_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_add_to_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_from_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    auto handle_users_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_groups_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_members_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_is_member_of_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"users", handle_users_op},
        {"groups", handle_groups_op},
        {"members", handle_members_op},
        {"is_member_of_group", handle_is_member_of_group_op},
        {"stat", handle_stat_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"create_user", handle_create_user_op},
        {"remove_user", handle_remove_user_op},
        {"set_password", handle_set_password_op},
        {"set_user_type", handle_set_user_type_op},
        {"add_user_auth", handle_add_user_auth_op},
        {"remove_user_auth", handle_remove_user_auth_op},
        {"create_group", handle_create_group_op},
        {"remove_group", handle_remove_group_op},
        {"add_to_group", handle_add_to_group_op},
        {"remove_from_group", handle_remove_from_group_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /users_groups.
    auto users_groups(session_pointer_type _sess_ptr, const request_type& _req) -> void
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
    } // users_groups
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_create_user_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto zone_iter = _args.find("zone");
            if (zone_iter == std::end(_args)) {
                log::error("{}: Missing [zone] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto user_type = adm::user_type::rodsuser;
            const auto user_type_iter = _args.find("user-type");
            if (user_type_iter != std::end(_args) && user_type_iter->second != "rodsuser") {
                if (user_type_iter->second == "rodsadmin") {
                    user_type = adm::user_type::rodsadmin;
                }
                else if (user_type_iter->second == "groupadmin") {
                    user_type = adm::user_type::groupadmin;
                }
                else {
                    log::error("{}: Invalid user-type.", __func__);
                    return irods::http::fail(res, http::status::bad_request);
                }
            }

            // TODO This can be derived if the REST API provides a way to know what zone it
            // is connected to. For example, the config file can define the local zone and then
            // we can use that to compare whether the client is attempting to create a local or
            // remote user.
            auto zone_type = adm::zone_type::local;
            const auto remote_iter = _args.find("remote_user");
            if (remote_iter != std::end(_args) && remote_iter->second == "1") {
                zone_type = adm::zone_type::remote;
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::add_user(conn, adm::user{name_iter->second, zone_iter->second}, user_type, zone_type);

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
    } // handle_create_user_op

    auto handle_remove_user_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto zone_iter = _args.find("zone");
            if (zone_iter == std::end(_args)) {
                log::error("{}: Missing [zone] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::remove_user(conn, adm::user{name_iter->second, zone_iter->second});

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
    } // handle_remove_user_op

    auto handle_set_password_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
        res.set(http::field::content_type, "application/json");
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
    } // handle_set_password_op

    auto handle_set_user_type_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
        res.set(http::field::content_type, "application/json");
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
    } // handle_set_user_type_op

    auto handle_add_user_auth_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
        res.set(http::field::content_type, "application/json");
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
    } // handle_add_user_auth_op

    auto handle_remove_user_auth_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
        res.set(http::field::content_type, "application/json");
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
    } // handle_remove_user_auth_op

    auto handle_create_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::add_group(conn, adm::group{name_iter->second});

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
    } // handle_create_group_op

    auto handle_remove_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::remove_group(conn, adm::group{name_iter->second});

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
    } // handle_remove_group_op

    auto handle_add_to_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto user_iter = _args.find("user");
            if (user_iter == std::end(_args)) {
                log::error("{}: Missing [user] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto group_iter = _args.find("group");
            if (group_iter == std::end(_args)) {
                log::error("{}: Missing [group] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            const auto zone_iter = _args.find("zone");
            if (zone_iter != std::end(_args)) {
                adm::client::add_user_to_group(conn, adm::group{group_iter->second}, adm::user{user_iter->second, zone_iter->second});
            }
            else {
                adm::client::add_user_to_group(conn, adm::group{group_iter->second}, adm::user{user_iter->second});
            }

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
    } // handle_add_to_group_op

    auto handle_remove_from_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto user_iter = _args.find("user");
            if (user_iter == std::end(_args)) {
                log::error("{}: Missing [user] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto group_iter = _args.find("group");
            if (group_iter == std::end(_args)) {
                log::error("{}: Missing [group] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            const auto zone_iter = _args.find("zone");
            if (zone_iter != std::end(_args)) {
                adm::client::remove_user_from_group(conn, adm::group{group_iter->second}, adm::user{user_iter->second, zone_iter->second});
            }
            else {
                adm::client::remove_user_from_group(conn, adm::group{group_iter->second}, adm::user{user_iter->second});
            }

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
    } // handle_remove_from_group_op

    auto handle_users_op(const irods::http::request_type& _req, const query_arguments_type&) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            auto conn = irods::get_connection(client_info->username);
            const auto users = adm::client::users(conn);

            std::vector<json> v;
            v.reserve(users.size());

            for (auto&& u : users) {
                v.push_back({
                    {"name", u.name},
                    {"zone", u.zone}
                });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }},
                {"users", v}
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
    } // handle_users_op

    auto handle_groups_op(const irods::http::request_type& _req, const query_arguments_type&) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            auto conn = irods::get_connection(client_info->username);
            auto groups = adm::client::groups(conn);

            std::vector<std::string> v;
            v.reserve(groups.size());

            for (auto&& g : groups) {
                v.push_back(std::move(g.name));
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }},
                {"groups", v}
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
    } // handle_groups_op

    auto handle_members_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
        res.set(http::field::content_type, "application/json");
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
    } // handle_members_op

    auto handle_is_member_of_group_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
        res.set(http::field::content_type, "application/json");
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
    } // handle_is_member_of_group_op

    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            json info{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"exists", false}
            };

            // If the zone parameter is provided, we're likely dealing with a user. Otherwise,
            // we don't know what we're identifying.
            const auto zone_iter = _args.find("zone");
            if (zone_iter != std::end(_args)) {
                const adm::user user{name_iter->second, zone_iter->second};
                if (const auto id = adm::client::id(conn, user); id) {
                    info.update({
                        {"exists", true},
                        {"id", *id},
                        {"type", adm::to_c_str(*adm::client::type(conn, user))}
                    });
                }

                res.body() = info.dump();
                res.prepare_payload();
                return res;
            }

            // The client did not include a zone so we are required to test if the name
            // identifies a user or group.

            const adm::user user{name_iter->second};
            if (const auto id = adm::client::id(conn, user); id) {
                info.update({
                    {"exists", true},
                    {"id", *id},
                    {"local_unique_name", adm::client::local_unique_name(conn, user)},
                    {"type", adm::to_c_str(*adm::client::type(conn, user))}
                });
            }

            const adm::group group{name_iter->second};
            if (const auto id = adm::client::id(conn, group); id) {
                info.update({
                    {"exists", true},
                    {"id", *id},
                    {"type", "rodsgroup"}
                });
            }

            res.body() = info.dump();
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
    } // handle_stat_op
} // anonymous namespace
