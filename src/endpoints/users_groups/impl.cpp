#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "shared_api_operations.hpp"
#include "version.hpp"

#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/user_administration.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <array>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace adm = irods::experimental::administration;
namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

#define IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(name) \
    auto name(irods::http::session_pointer_type _sess_ptr, irods::http::request_type& _req, irods::http::query_arguments_type& _args) -> void

namespace
{
    using handler_type = void(*)(irods::http::session_pointer_type, irods::http::request_type&, irods::http::query_arguments_type&);

    //
    // Handler function prototypes
    //

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_create_user_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_user_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_set_password_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_set_user_type_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_add_user_auth_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_user_auth_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_modify_metadata_op);

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_create_group_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_group_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_add_to_group_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_from_group_op);

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_users_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_groups_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_members_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_is_member_of_group_op);
    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_stat_op);

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
        {"remove_from_group", handle_remove_from_group_op},
        {"modify_metadata", handle_modify_metadata_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(users_groups)
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
    } // users_groups
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_create_user_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
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
                        log::error("{}: Invalid user-type.", fn);
                        return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                    }
                }

                auto zone_type = adm::zone_type::local;
                if (const auto& client = irods::http::globals::configuration().at("irods_client");
                    zone_iter->second != client.at("zone").get_ref<const std::string&>())
                {
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_create_user_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_user_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_remove_user_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_set_password_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto new_password_iter = _args.find("new-password");
                if (new_password_iter == std::end(_args)) {
                    log::error("{}: Missing [new-password] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                static const auto& proxy_user_password = irods::http::globals::configuration().at(json::json_pointer{"/irods_client/proxy_admin_account/password"}).get_ref<const std::string&>();
                const adm::user_password_property prop{new_password_iter->second, proxy_user_password};

                auto conn = irods::get_connection(client_info->username);
                adm::client::modify_user(conn, adm::user{name_iter->second, zone_iter->second}, prop);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0}
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_set_password_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_set_user_type_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto new_user_type_iter = _args.find("new-user-type");
                if (new_user_type_iter == std::end(_args)) {
                    log::error("{}: Missing [new-user-type] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const adm::user_type_property prop{adm::to_user_type(new_user_type_iter->second)};

                auto conn = irods::get_connection(client_info->username);
                adm::client::modify_user(conn, adm::user{name_iter->second, zone_iter->second}, prop);

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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_set_user_type_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_add_user_auth_op)
    {
#if 0
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
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

            return _sess_ptr->send(std::move(res));
        });
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
#endif
    } // handle_add_user_auth_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_user_auth_op)
    {
#if 0
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
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

            return _sess_ptr->send(std::move(res));
        });
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
#endif
    } // handle_remove_user_auth_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_create_group_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_create_group_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_group_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_remove_group_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_add_to_group_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto user_iter = _args.find("user");
                if (user_iter == std::end(_args)) {
                    log::error("{}: Missing [user] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto group_iter = _args.find("group");
                if (group_iter == std::end(_args)) {
                    log::error("{}: Missing [group] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);
                adm::client::add_user_to_group(conn, adm::group{group_iter->second}, adm::user{user_iter->second, zone_iter->second});

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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_add_to_group_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_remove_from_group_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto user_iter = _args.find("user");
                if (user_iter == std::end(_args)) {
                    log::error("{}: Missing [user] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto group_iter = _args.find("group");
                if (group_iter == std::end(_args)) {
                    log::error("{}: Missing [group] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);
                adm::client::remove_user_from_group(conn, adm::group{group_iter->second}, adm::user{user_iter->second, zone_iter->second});

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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_remove_from_group_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_users_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_users_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_groups_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_groups_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_members_op)
    {
#if 0
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
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

            return _sess_ptr->send(std::move(res));
        });
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return _sess_ptr->send(irods::http::fail(http::status::not_implemented));
#endif
    } // handle_members_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_is_member_of_group_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto group_iter = _args.find("group");
                if (group_iter == std::end(_args)) {
                    log::error("{}: Missing [group] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto user_iter = _args.find("user");
                if (user_iter == std::end(_args)) {
                    log::error("{}: Missing [user] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                const auto zone_iter = _args.find("zone");
                if (zone_iter == std::end(_args)) {
                    log::error("{}: Missing [zone] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
                }

                auto conn = irods::get_connection(client_info->username);

                const adm::group group{adm::group{group_iter->second}};
                const adm::user user{adm::user{user_iter->second, zone_iter->second}};

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0}
                    }},
                    {"is_member", adm::client::user_is_member_of_group(conn, group, user)}
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
    } // handle_is_member_of_group_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_stat_op)
    {
        auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return _sess_ptr->send(std::move(*result.response));
        }

        const auto* client_info = result.client_info;

        irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
            log::info("{}: client_info->username = [{}]", fn, client_info->username);

            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, irods::http::version::server_name);
            res.set(http::field::content_type, "application/json");
            res.keep_alive(_req.keep_alive());

            try {
                const auto name_iter = _args.find("name");
                if (name_iter == std::end(_args)) {
                    log::error("{}: Missing [name] parameter.", fn);
                    return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
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
                            {"local_unique_name", fmt::format("{}#{}", name_iter->second, zone_iter->second)},
                            {"type", adm::to_c_str(*adm::client::type(conn, user))}
                        });
                    }

                    res.body() = info.dump();
                    res.prepare_payload();
                    return _sess_ptr->send(std::move(res));
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
                else {
                    const adm::group group{name_iter->second};
                    if (const auto id = adm::client::id(conn, group); id) {
                        info.update({
                            {"exists", true},
                            {"id", *id},
                            {"type", "rodsgroup"}
                        });
                    }
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

            return _sess_ptr->send(std::move(res));
        });
    } // handle_stat_op

    IRODS_HTTP_API_HANDLER_FUNCTION_SIGNATURE(handle_modify_metadata_op)
    {
        using namespace irods::http::shared_api_operations;
        return op_atomic_apply_metadata_operations(_sess_ptr, _req, _args, entity_type::user);
    } // handle_modify_metadata_op
} // anonymous namespace
