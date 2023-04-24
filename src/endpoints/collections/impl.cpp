#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"

#include <irods/client_connection.hpp>
#include <irods/filesystem.hpp>
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
//namespace net   = boost::asio;      // from <boost/asio.hpp>

//using tcp = boost::asio::ip::tcp;   // from <boost/asio/ip/tcp.hpp> // TODO Remove

namespace fs  = irods::experimental::filesystem;
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
    auto handle_rename_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_set_permission_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"list", handle_list_op},
        {"stat", handle_stat_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"create", handle_create_op},
        {"remove", handle_remove_op},
        {"rename", handle_rename_op},
        {"set_permission", handle_set_permission_op}
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /collections.
    auto collections(const request_type& _req) -> response_type
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
    } // collections
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_list_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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

            irods::experimental::client_connection conn;

            if (!fs::client::is_collection(conn, lpath_iter->second)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_COLLECTION}
                    }}
                }.dump());
            }

            json entries;

            const auto recursive_iter = _args.find("recurse");
            if (recursive_iter != std::end(_args) && recursive_iter->second == "1") {
                for (auto&& e : fs::client::recursive_collection_iterator{conn, lpath_iter->second}) {
                    entries.push_back(e.path().c_str());
                }
            }
            else {
                for (auto&& e : fs::client::collection_iterator{conn, lpath_iter->second}) {
                    entries.push_back(e.path().c_str());
                }
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"entries", entries}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
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
    } // handle_list_op

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
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            const auto status = fs::client::status(conn, lpath_iter->second);

            if (!fs::client::is_collection(status)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_COLLECTION}
                    }}
                }.dump());
            }

            json perms;
            for (auto&& ep : status.permissions()) {
                perms.push_back(json{
                    {"name", ep.name},
                    {"zone", ep.zone},
                    {"type", ep.type},
                    {"perm", irods::to_permission_string(ep.prms)},
                });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"type", irods::to_object_type_string(status.type())},
                {"inheritance_enabled", status.is_inheritance_enabled()},
                {"permissions", perms},
                // TODO Notice these require additional network calls. Could be avoided by using GenQuery, perhaps.
                {"registered", fs::client::is_collection_registered(conn, lpath_iter->second)},
                {"modified_at", fs::client::last_write_time(conn, lpath_iter->second).time_since_epoch().count()}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
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

            auto conn = irods::get_connection(client_info->username);
            fs::client::create_collections(conn, lpath_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
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
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            if (!fs::client::is_collection(conn, lpath_iter->second)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_COLLECTION}
                    }}
                }.dump());
            }

            fs::remove_options opts = fs::remove_options::none;

            const auto no_trash_iter = _args.find("no-trash");
            if (no_trash_iter != std::end(_args) && no_trash_iter->second == "1") {
                opts = fs::remove_options::no_trash;
            }

            const auto recursive_iter = _args.find("recurse");
            if (recursive_iter != std::end(_args) && recursive_iter->second == "1") {
                fs::client::remove_all(conn, lpath_iter->second, opts);
            }
            else {
                fs::client::remove(conn, lpath_iter->second, opts);
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
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

    auto handle_rename_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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
            const auto old_lpath_iter = _args.find("old-lpath");
            if (old_lpath_iter == std::end(_args)) {
                log::error("{}: Missing [old-lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            auto conn = irods::get_connection(client_info->username);

            if (!fs::client::is_collection(conn, old_lpath_iter->second)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_COLLECTION}
                    }}
                }.dump());
            }

            const auto new_lpath_iter = _args.find("new-lpath");
            if (new_lpath_iter == std::end(_args)) {
                log::error("{}: Missing [new-lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            try {
                fs::client::rename(conn, old_lpath_iter->second, new_lpath_iter->second);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.result(http::status::bad_request);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
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
    } // handle_rename_op

    auto handle_set_permission_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
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

            auto conn = irods::get_connection(client_info->username);

            if (!fs::client::is_collection(conn, lpath_iter->second)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_COLLECTION}
                    }}
                }.dump());
            }

            const auto entity_name_iter = _args.find("entity-name");
            if (entity_name_iter == std::end(_args)) {
                log::error("{}: Missing [entity-name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto perm_iter = _args.find("permission");
            if (perm_iter == std::end(_args)) {
                log::error("{}: Missing [permission] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto perm_enum = irods::to_permission_enum(perm_iter->second);
            if (!perm_enum) {
                log::error("{}: Invalid value for [permission] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            try {
                const auto admin_mode_iter = _args.find("admin");
                if (admin_mode_iter != std::end(_args) && admin_mode_iter->second == "1") {
                    fs::client::permissions(fs::admin, conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
                }
                else {
                    fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
                }

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0},
                    }}
                }.dump();
            }
            catch (const fs::filesystem_error& e) {
                res.body() = json{
                    {"irods_response", {
                        {"error_code", e.code().value()},
                        {"error_message", e.what()}
                    }}
                }.dump();
            }
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
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
    } // handle_set_permission_op
} // anonymous namespace
