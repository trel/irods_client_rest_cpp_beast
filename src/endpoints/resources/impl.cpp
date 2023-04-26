#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/resource_administration.hpp>
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

    auto handle_create_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_modify_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_add_child_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_child_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_rebalance_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"stat", handle_stat_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"create", handle_create_op},
        {"remove", handle_remove_op},
        {"modify", handle_modify_op},
        {"add_child", handle_add_child_op},
        {"remove_child", handle_remove_child_op},
        {"rebalance", handle_rebalance_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /resources.
    auto resources(session_pointer_type _sess_ptr, const request_type& _req) -> void
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
    } // resources
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

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
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            const auto type_iter = _args.find("type");
            if (type_iter == std::end(_args)) {
                log::error("{}: Missing [type] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            adm::resource_registration_info resc_info;
            resc_info.resource_name = name_iter->second;
            resc_info.resource_type = type_iter->second;

            const auto host_iter = _args.find("host");
            if (host_iter != std::end(_args)) {
                resc_info.host_name = host_iter->second;
            }

            const auto vault_path_iter = _args.find("vault-path");
            if (vault_path_iter != std::end(_args)) {
                resc_info.vault_path = vault_path_iter->second;
            }

            const auto ctx_iter = _args.find("context");
            if (ctx_iter != std::end(_args)) {
                resc_info.context_string = ctx_iter->second;
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::add_resource(conn, resc_info);

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
        res.set(http::field::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        try {
            const auto name_iter = _args.find("name");
            if (name_iter == std::end(_args)) {
                log::error("{}: Missing [name] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::remove_resource(conn, name_iter->second);

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

    auto handle_modify_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
    } // handle_modify_op

    auto handle_add_child_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
            const auto parent_name_iter = _args.find("parent-name");
            if (parent_name_iter == std::end(_args)) {
                log::error("{}: Missing [parent-name] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            const auto child_name_iter = _args.find("child-name");
            if (child_name_iter == std::end(_args)) {
                log::error("{}: Missing [child-name] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            const auto ctx_iter = _args.find("context");
            if (ctx_iter != std::end(_args)) {
                adm::client::add_child_resource(conn, parent_name_iter->second, child_name_iter->second, ctx_iter->second);
            }
            else {
                adm::client::add_child_resource(conn, parent_name_iter->second, child_name_iter->second);
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
    } // handle_add_child_op

    auto handle_remove_child_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
            const auto parent_name_iter = _args.find("parent-name");
            if (parent_name_iter == std::end(_args)) {
                log::error("{}: Missing [parent-name] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            const auto child_name_iter = _args.find("child-name");
            if (child_name_iter == std::end(_args)) {
                log::error("{}: Missing [child-name] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::remove_child_resource(conn, parent_name_iter->second, child_name_iter->second);

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
    } // handle_remove_child_op

    auto handle_rebalance_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
                return irods::http::fail(http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);
            adm::client::rebalance_resource(conn, name_iter->second);

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
    } // handle_rebalance_op

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
                return irods::http::fail(http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            json::object_t info;
            bool exists = false;

            if (const auto resc = adm::client::resource_info(conn, name_iter->second); resc) {
                exists = true;

                info = { // TODO Can't use += yet :-(
                    {"id", resc->id()},
                    {"name", resc->name()},
                    {"type", resc->type()},
                    {"zone", resc->zone_name()},
                    {"host", resc->host_name()},
                    {"vault_path", resc->vault_path()},
                    {"status", resc->status()},
                    {"context", resc->context_string()},
                    {"comments", resc->comments()},
                    {"information", resc->information()},
                    {"free_space", resc->free_space()},
                    {"free_space_last_modified", resc->free_space_last_modified().time_since_epoch().count()},
                    {"parent_id", resc->parent_id()},
                    {"created", resc->created().time_since_epoch().count()},
                    {"last_modified", resc->last_modified().time_since_epoch().count()}
                };
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"exists", exists},
                {"info", info}
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
    } // handle_stat_op
} // anonymous namespace
