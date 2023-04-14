#include <irods/atomic_apply_metadata_operations.h>
#include <irods/base64.hpp>
#include <irods/client_connection.hpp>
#include <irods/execCmd.h>
#include <irods/execMyRule.h>
#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/msParam.h>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h>
#include <irods/resource_administration.hpp>
#include <irods/rodsClient.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/ruleExecDel.h>
#include <irods/touch.h>
#include <irods/user_administration.hpp>

#include <irods/transport/default_transport.hpp>
#include <irods/dstream.hpp>

#include <curl/curl.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <string>
#include <string_view>
#include <utility>
#include <unordered_map>
#include <fstream>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

using response        = http::response<http::string_body>;
using request_handler = std::function<response (const http::request<http::string_body>&)>;

using json = nlohmann::json;

struct url
{
    std::string path;
    std::unordered_map<std::string, std::string> query;
};

struct basic_auth_credentials
{
    std::string username;
    std::string password; // TODO Probably not needed.
    // TODO Store an expiration timestamp here.
};

std::unordered_map<std::string, basic_auth_credentials> authenticated_client_info;

auto generate_uuid() -> std::string
{
    std::string uuid;
    uuid.reserve(36); // NOLINT(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
    uuid = to_string(boost::uuids::random_generator{}());

    while (authenticated_client_info.find(uuid) != std::end(authenticated_client_info)) {
        uuid = to_string(boost::uuids::random_generator{}());
    }

    return uuid;
}

auto decode(const std::string_view _v) -> std::string
{
    std::string result;
    int decoded_length = -1;

    if (auto* decoded = curl_easy_unescape(nullptr, _v.data(), _v.size(), &decoded_length); decoded) {
        result = decoded;
        curl_free(decoded);
    }
    else {
        result.assign(_v);
    }

    return result;
}

auto parse_url(const http::request<http::string_body>& _req) -> url
{
    // TODO Show how to parse URLs using libcurl.
    // See https://curl.se/libcurl/c/parseurl.html for an example.
    auto* curl = curl_url();

    if (!curl) {
        // TODO Report internal server error.
    }

    // Include a bogus prefix. We only care about the path and query parts of the URL.
    const auto url_to_parse = fmt::format("http://ignored{}", _req.target());
    if (const auto ec = curl_url_set(curl, CURLUPART_URL, url_to_parse.c_str(), 0); ec) {
        // TODO Report error.
        fmt::print("error: {}\n", ec);
    }

    url url;

    // Extract the path.
    // This is what we use to route requests to the various endpoints.
    char* path{};
    if (const auto ec = curl_url_get(curl, CURLUPART_PATH, &path, 0); ec == 0) {
        if (path) {
            url.path = path;
            curl_free(path);
        }
    }
    else {
        // TODO Report error.
        fmt::print("error: {}\n", ec);
    }

    // Extract the query.
    // ChatGPT states that the values in the key value pairs must escape embedded equal signs.
    // This allows the HTTP server to parse the query string correctly. Therefore, we don't have
    // to protect against that case. The client must send the correct URL escaped input.
    char* query{};
    if (const auto ec = curl_url_get(curl, CURLUPART_QUERY, &query, 0); ec == 0) {
        if (query) {
            // I really wish Boost.URL was part of Boost 1.78. Things would be so much easier.
            // Sadly, we have to release an updated Boost external to get it.
            try {
                std::vector<std::string> tokens;
                boost::split(tokens, query, boost::is_any_of("&"));

                std::vector<std::string> kvp;
                
                for (auto&& t : tokens) {
                    boost::split(kvp, t, boost::is_any_of("="));

                    if (kvp.size() == 2) {
                        url.query.insert_or_assign(std::move(kvp[0]), decode(kvp[1]));
                    }
                    else if (kvp.size() == 1) {
                        url.query.insert_or_assign(std::move(kvp[0]), "");
                    }

                    kvp.clear();
                }
            }
            catch (const std::exception& e) {
                // TODO
                fmt::print("exception: {}\n", e.what());
            }

            curl_free(query);
        }
    }
    else {
        // TODO
        fmt::print("error: {}\n", ec);
    }

    return url;
}

auto handle_auth(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    // TODO Authentication needs to be implemented as a pluggable interface.
    // Out of the box, the REST API will support Basic authentication. Later,
    // we add OIDC (and more, perhaps).

    // OIDC authentication for this REST API may require a mapping between a
    // value in the returned ID/access token and a user in iRODS. For example:
    //
    //   {
    //       // The claim to use.
    //       // This may require use of multiple claims.
    //       "claim": "email",
    //
    //       // The user mapping.
    //       "users": {
    //           "alice@ymail.com": {
    //               "username": "alice",
    //               "zone": "tempZone"
    //           }
    //           "bob@ymail.com": {
    //               "username": "bob#otherZone",
    //               "zone": "tempZone"
    //           }
    //       }
    //   }
    //
    // This assumes the OIDC Provider (OP) always defines an email claim. 

    if (_req.method() != http::verb::post) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    //
    // TODO Here is where we determine what form of authentication to perform (e.g. Basic or OIDC).
    //

    auto pos = iter->value().find("Basic ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string authorization{iter->value().substr(pos + 6)};
    boost::trim(authorization);
    fmt::print("{}: Authorization value (trimmed): [{}]\n", __func__, authorization);

    std::vector<std::uint8_t> creds;
    creds.resize(128);
    unsigned long size = 128;
    const auto ec = irods::base64_decode((unsigned char*) authorization.data(), authorization.size(), creds.data(), &size);
    fmt::print("{}: base64 error code         = [{}]\n", __func__, ec);
    fmt::print("{}: base64 decoded size       = [{}]\n", __func__, size);

    std::string_view sv{(char*) creds.data(), size}; 
    fmt::print("{}: base64 decode credentials = [{}]\n", __func__, sv);

    const auto colon = sv.find(':');
    if (colon == std::string_view::npos) {
        fmt::print("{}: Invalid format for credentials. Expected: <username>:<password>.\n", __func__);
        http::response<http::string_body> res{http::status::unauthorized, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string username{sv.substr(0, colon)};
    std::string password{sv.substr(colon + 1)};
    fmt::print("{}: username = [{}]\n", __func__, username);
    fmt::print("{}: password = [{}]\n", __func__, password);

    bool login_successful = false;

    rErrMsg_t error{};
    if (auto* comm = rcConnect("localhost", 1247, username.c_str(), "tempZone", 0, &error); comm) {
        // TODO client_connection library needs support for logging in via a password.
        //
        // This call will print "rcAuthResponse failed with error -826000 CAT_INVALID_AUTHENTICATION"
        // to the terminal when given a bad password. It shouldn't do that.
        login_successful = (clientLoginWithPassword(comm, password.data()) == 0);
        rcDisconnect(comm);
    }

    if (!login_successful) {
        http::response<http::string_body> res{http::status::unauthorized, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    // TODO If login succeeded, generate a token (i.e. JWT) that represents the
    // authenticated user. The client is now required to pass the token back to the
    // server when executing requests.
    //
    // The token will be mapped to an object that contains information needed to
    // execute operations on the iRODS server. The object will likely contain the user's
    // iRODS username and password.

    // TODO These bearer tokens need an expiration date. Should their lifetime be extended
    // on each interaction with the server or should they be extended on each successful
    // operation. Perhaps they shouldn't be extended at all.
    //
    // Research this.
    const auto bearer_token = generate_uuid();
    authenticated_client_info.insert({bearer_token, {.username = std::move(username)}});

    // TODO Parse the header value and determine if the user is allowed to access.
    // 
    // Q. For Basic authorization, is it better to store an iRODS connection in memory
    // for the duration of the user's session? Or, is it better to connect and then
    // disconnect for each request?
    // 
    // A. My first thought is it is probably better to connect/disconnect so that the
    // remote server's connections aren't exhausted (i.e. consider what else may be
    // happening on the remote server). However, using a connection pool along with
    // rc_switch_user is likely the correct answer. That and exposing server options
    // which allow an administrator to tune the number of connections and threads. By
    // exposing server options, we let the system administrator make the decision,
    // which is a good thing.

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());
    res.body() = bearer_token;
    res.prepare_payload();
    return res;
}

auto handle_collections(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    //
    // Extract the Bearer token from the Authorization header.
    //

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    auto pos = iter->value().find("Bearer ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string bearer_token{iter->value().substr(pos + 7)};
    boost::trim(bearer_token);
    fmt::print("{}: Bearer token: [{}]\n", __func__, bearer_token);

    // Verify the bearer token is known to the server. If not, return an error.
    {
        const auto iter = authenticated_client_info.find(bearer_token);
        if (iter == std::end(authenticated_client_info)) {
            fmt::print("{}: Could not find bearer token matching [{}].\n", __func__, bearer_token);
            http::response<http::string_body> res{http::status::unauthorized, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }
    }

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        fmt::print("{}: Missing [op] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    const auto lpath_iter = url.query.find("lpath");
    if (lpath_iter == std::end(url.query)) {
        fmt::print("{}: Missing [lpath] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};

    namespace fs = irods::experimental::filesystem;

    // TODO This must be a proxied connection.
    irods::experimental::client_connection conn;

    if (op_iter->second == "create") {
        try {
            fs::client::create_collection(conn, lpath_iter->second);
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
    }
    else if (op_iter->second == "remove") {
        try {
            fs::remove_options opts = fs::remove_options::none;

            const auto no_trash_iter = url.query.find("no-trash");
            if (no_trash_iter != std::end(url.query) && no_trash_iter->second == "1") {
                opts = fs::remove_options::no_trash;
            }

            const auto recursive_iter = url.query.find("recurse");
            if (recursive_iter != std::end(url.query) && recursive_iter->second == "1") {
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
    }
    else if (op_iter->second == "list") {
        try {
            json entries;

            const auto recursive_iter = url.query.find("recurse");
            if (recursive_iter != std::end(url.query) && recursive_iter->second == "1") {
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
    }
    else if (op_iter->second == "rename") {
        const auto new_lpath_iter = url.query.find("new-lpath");
        if (new_lpath_iter == std::end(url.query)) {
            fmt::print("{}: Missing [new_lpath] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::bad_request, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            fs::client::rename(conn, lpath_iter->second, new_lpath_iter->second);
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
    else if (op_iter->second == "set-permission") {
        const auto entity_name_iter = url.query.find("entity-name");
        if (entity_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [entity-name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::bad_request, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        const auto perm_iter = url.query.find("permission");
        if (perm_iter == std::end(url.query)) {
            fmt::print("{}: Missing [permission] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::bad_request, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            const auto admin_mode_iter = url.query.find("admin");
            if (admin_mode_iter != std::end(url.query) && admin_mode_iter->second == "1") {
                fs::client::permissions(fs::admin, conn, lpath_iter->second, entity_name_iter->second, fs::perms::own);
            }
            else {
                fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, fs::perms::own);
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
    else if (op_iter->second == "stat") {
        try {
            const auto status = fs::client::status(conn, lpath_iter->second);

            const auto to_permission_string = [](const fs::perms _p)
            {
                switch (_p) {
                    case fs::perms::null:            return "null";
                    case fs::perms::read_metadata:   return "read_metadata";
                    case fs::perms::read_object:     return "read_object";
                    case fs::perms::read:            return "read_object";
                    case fs::perms::create_metadata: return "create_metadata";
                    case fs::perms::modify_metadata: return "modify_metadata";
                    case fs::perms::delete_metadata: return "delete_metadata";
                    case fs::perms::create_object:   return "create_object";
                    case fs::perms::modify_object:   return "modify_object";
                    case fs::perms::write:           return "modify_object";
                    case fs::perms::delete_object:   return "delete_object";
                    case fs::perms::own:             return "own";
                    default:                         return "?"; // TODO std::unreachable() or __builtin_unreachable()
                }
            };

            const auto to_type_string = [](const fs::object_type _t)
            {
                switch (_t) {
                    case fs::object_type::collection:         return "collection";
                    case fs::object_type::data_object:        return "data_object";
                    case fs::object_type::none:               return "none";
                    case fs::object_type::not_found:          return "not_found";
                    case fs::object_type::special_collection: return "special_collection";
                    case fs::object_type::unknown:            return "unknown";
                    default:                                  return "?";
                }
            };

            json perms;
            for (auto&& ep : status.permissions()) {
                perms.push_back(json{
                    {"name", ep.name},
                    {"zone", ep.zone},
                    {"type", ep.type},
                    {"perm", to_permission_string(ep.prms)},
                });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"type", to_type_string(status.type())},
                {"inheritance_enabled", status.is_inheritance_enabled()},
                {"permissions", perms}
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

    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());
    res.prepare_payload();
    return res;
}

auto handle_data_objects(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    //
    // Extract the Bearer token from the Authorization header.
    //

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    auto pos = iter->value().find("Bearer ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string bearer_token{iter->value().substr(pos + 7)};
    boost::trim(bearer_token);
    fmt::print("{}: Bearer token: [{}]\n", __func__, bearer_token);

    // Verify the bearer token is known to the server. If not, return an error.
    [[maybe_unused]] const std::string* username{};
    {
        const auto iter = authenticated_client_info.find(bearer_token);
        if (iter == std::end(authenticated_client_info)) {
            fmt::print("{}: Could not find bearer token matching [{}].\n", __func__, bearer_token);
            http::response<http::string_body> res{http::status::unauthorized, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        username = &iter->second.username;
    }

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        fmt::print("{}: Missing [op] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    const auto lpath_iter = url.query.find("lpath");
    if (lpath_iter == std::end(url.query)) {
        fmt::print("{}: Missing [lpath] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    if (op_iter->second == "read") {
        // TODO Inputs:
        // - offset
        // - count
        //     - content-length vs query parameter
        //     - How about chunked encoding?
        //
        // TODO Should a client care about a specific replica when reading?
        // TODO Should a client be allowed to target a leaf resource?

        try {
            irods::experimental::client_connection conn;

            namespace io = irods::experimental::io;

            io::client::native_transport tp{conn};
            io::idstream in{tp, lpath_iter->second};

            if (!in) {
                // TODO
            }

            auto iter = url.query.find("offset");
            if (iter != std::end(url.query)) {
                try {
                    in.seekg(std::stoll(iter->second));
                }
                catch (const std::exception& e) {
                    // TODO
                }
            }

            std::vector<char> buffer;

            iter = url.query.find("count");
            if (iter != std::end(url.query)) {
                try {
                    buffer.resize(std::stoi(iter->second));
                }
                catch (const std::exception& e) {
                    // TODO
                }
            }
            else {
                buffer.resize(8192);
            }

            in.read(buffer.data(), buffer.size());

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }},
                {"bytes_read", in.gcount()},
                {"data", buffer}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "write") {
        // TODO Inputs:
        // - transfer-handle
        // - offset
        // - count
        //     - content-length vs query parameter
        //     - How about chunked encoding?
        //
        // TODO Should a client care about a specific replica when reading?
        // TODO Should a client be allowed to target a leaf resource?

        try {
            irods::experimental::client_connection conn;

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "parallel-write-init") {
        // TODO
        // 1. Create a parallel transfer context (PTC).
        // 2. Open one iRODS connection per stream and store in the PTC.
        // 3. Generate a transfer handle and associate it with the Bearer/Access token and PTC.
        // 4. Return transfer handle to client.
        //
        // The client is now free to call the write operation as much as they want.
    }
    else if (op_iter->second == "parallel-write-shutdown") {
        // TODO
        // 1. Verify transfer handle and lookup PTC.
        // 2. Close all streams in reverse order.
        // 3. Disassociate the transfer handle and PTC.
        // 4. Free resources.
    }
    else if (op_iter->second == "replicate") {
        const auto dst_resc_iter = url.query.find("dst-resource");
        if (dst_resc_iter == std::end(url.query)) {
            fmt::print("{}: Missing [dst-resource] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            DataObjInp input{};
            irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};
            std::strncpy(input.objPath, lpath_iter->second.c_str(), sizeof(DataObjInp::objPath));
            addKeyVal(&input.condInput, DEST_RESC_NAME_KW, dst_resc_iter->second.c_str());

            irods::experimental::client_connection conn;
            const auto ec = rcDataObjRepl(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", "An unexpected error occurred while processing the request."}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "trim") {
        const auto resc_iter = url.query.find("resource");
        if (resc_iter == std::end(url.query)) {
            fmt::print("{}: Missing [resource] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::bad_request, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            DataObjInp input{};
            irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};
            std::strncpy(input.objPath, lpath_iter->second.c_str(), sizeof(DataObjInp::objPath));
            addKeyVal(&input.condInput, RESC_NAME_KW, resc_iter->second.c_str());

            if (const auto iter = url.query.find("admin"); iter != std::end(url.query) && iter->second == "1") {
                addKeyVal(&input.condInput, ADMIN_KW, "");
            }

            irods::experimental::client_connection conn;
            const auto ec = rcDataObjTrim(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", "An unexpected error occurred while processing the request."}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "set-permission") {
        const auto entity_name_iter = url.query.find("entity-name");
        if (entity_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [entity-name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::bad_request, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        const auto perm_iter = url.query.find("permission");
        if (perm_iter == std::end(url.query)) {
            fmt::print("{}: Missing [permission] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::bad_request, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        namespace fs = irods::experimental::filesystem;

        try {
            irods::experimental::client_connection conn;

            const auto admin_mode_iter = url.query.find("admin");
            if (admin_mode_iter != std::end(url.query) && admin_mode_iter->second == "1") {
                fs::client::permissions(fs::admin, conn, lpath_iter->second, entity_name_iter->second, fs::perms::own);
            }
            else {
                fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, fs::perms::own);
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
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "stat") {
        namespace fs = irods::experimental::filesystem;

        try {
            irods::experimental::client_connection conn;
            const auto status = fs::client::status(conn, lpath_iter->second);

            const auto to_permission_string = [](const fs::perms _p)
            {
                switch (_p) {
                    case fs::perms::null:            return "null";
                    case fs::perms::read_metadata:   return "read_metadata";
                    case fs::perms::read_object:     return "read_object";
                    case fs::perms::read:            return "read_object";
                    case fs::perms::create_metadata: return "create_metadata";
                    case fs::perms::modify_metadata: return "modify_metadata";
                    case fs::perms::delete_metadata: return "delete_metadata";
                    case fs::perms::create_object:   return "create_object";
                    case fs::perms::modify_object:   return "modify_object";
                    case fs::perms::write:           return "modify_object";
                    case fs::perms::delete_object:   return "delete_object";
                    case fs::perms::own:             return "own";
                    default:                         return "?"; // TODO std::unreachable() or __builtin_unreachable()
                }
            };

            const auto to_type_string = [](const fs::object_type _t)
            {
                switch (_t) {
                    case fs::object_type::collection:         return "collection";
                    case fs::object_type::data_object:        return "data_object";
                    case fs::object_type::none:               return "none";
                    case fs::object_type::not_found:          return "not_found";
                    case fs::object_type::special_collection: return "special_collection";
                    case fs::object_type::unknown:            return "unknown";
                    default:                                  return "?";
                }
            };

            json perms;
            for (auto&& ep : status.permissions()) {
                perms.push_back(json{
                    {"name", ep.name},
                    {"zone", ep.zone},
                    {"type", ep.type},
                    {"perm", to_permission_string(ep.prms)},
                });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"type", to_type_string(status.type())},
                //{"inheritance_enabled", status.is_inheritance_enabled()},
                {"permissions", perms},
                // TODO Should these be returned upon request?
                // What should be included under replicas? Data ID, physical path, replica status, replica number? What else?
                {"replicas", json::array_t{}}
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
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", "An unexpected error occurred while processing the request."}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "register") {
        // TODO Notes:
        // - Physical path is set via FILE_PATH_KW
        // - Destination resource is set via DEST_RESC_NAME_KW
        // - Registering a "replica" requires setting REG_REPL_KW
        // - Must be on the server unless the data size is provided (DATA_SIZE_KW)
        // - Must support checksums and verification (i.e. REG_CHKSUM_KW, VERIFY_CHKSUM_KW)
        // - Must support the force flag (i.e. FORCE_FLAG_KW)
        // - Can't support collections and recursive flag
        //
        // See regUtil.cpp for more details.
    }
    else if (op_iter->second == "unregister") {
        // TODO So we don't have a dedicated API for this. Unregistering replicas feels like it should
        // be a real API. iunreg relies on trimUtil() and rmUtil() to do its job.
    }
    else if (op_iter->second == "remove") {
        namespace fs = irods::experimental::filesystem;

        try {
            irods::experimental::client_connection conn;

            if (!fs::client::is_data_object(conn, lpath_iter->second)) {
                fmt::print("{}: Not a data object.\n", __func__);
                http::response<http::string_body> res{http::status::bad_request, _req.version()};
                res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                res.set(http::field::content_type, "text/plain");
                res.set(http::field::content_length, "0");
                res.keep_alive(_req.keep_alive());
                return res;
            }

            fs::remove_options opts = fs::remove_options::none;

            if (const auto iter = url.query.find("no-trash"); iter != std::end(url.query) && iter->second == "1") {
                opts = fs::remove_options::no_trash;
            }

            // There's no admin flag for removal.
            fs::client::remove(conn, lpath_iter->second, opts);
        }
        catch (const fs::filesystem_error& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "touch") {
        try {
            json::object_t options;

            auto opt_iter = url.query.find("no-create");
            if (opt_iter != std::end(url.query)) {
                options["no_create"] = (opt_iter->second == "1");
            }

            opt_iter = url.query.find("replica-number");
            if (opt_iter != std::end(url.query)) {
                try {
                    options["replica_number"] = std::stoi(opt_iter->second);
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not convert replica-number [{}] into an integer.", __func__, opt_iter->second);
                }
            }

            opt_iter = url.query.find("leaf-resource");
            if (opt_iter != std::end(url.query)) {
                options["leaf_resource_name"] = opt_iter->second;
            }

            opt_iter = url.query.find("seconds-since-epoch");
            if (opt_iter != std::end(url.query)) {
                try {
                    options["seconds_since_epoch"] = std::stoi(opt_iter->second);
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not convert seconds-since-epoch [{}] into an integer.", __func__, opt_iter->second);
                }
            }

            opt_iter = url.query.find("reference");
            if (opt_iter != std::end(url.query)) {
                options["reference"] = opt_iter->second;
            }

            const json input{
                {"logical_path", lpath_iter->second.c_str()},
                {"options", options}
            };

            irods::experimental::client_connection conn;
            const auto ec = rc_touch(static_cast<RcComm*>(conn), input.dump().c_str());

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_metadata(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    //
    // Extract the Bearer token from the Authorization header.
    //

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    auto pos = iter->value().find("Bearer ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string bearer_token{iter->value().substr(pos + 7)};
    boost::trim(bearer_token);
    fmt::print("{}: Bearer token: [{}]\n", __func__, bearer_token);

    // Verify the bearer token is known to the server. If not, return an error.
    [[maybe_unused]] const std::string* username{};
    {
        const auto iter = authenticated_client_info.find(bearer_token);
        if (iter == std::end(authenticated_client_info)) {
            fmt::print("{}: Could not find bearer token matching [{}].\n", __func__, bearer_token);
            http::response<http::string_body> res{http::status::unauthorized, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        username = &iter->second.username;
    }

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        fmt::print("{}: Missing [op] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    // TODO This atomic metadata endpoint feels like it should be part of the other endpoints
    // rather than its own. Consider merging it. If it is merged, the command can become the
    // following:
    //
    //     /data-objects?op=apply_metadata_operations
    //
    // However, this one endpoint already covers all iRODS entities.
    if (op_iter->second == "atomic_execute") {
        try {
            irods::experimental::client_connection conn;

            const auto& atomic_ops = _req.body();
            char* output{};
            irods::at_scope_exit_unsafe free_output{[&output] { std::free(output); }};

            const auto ec = rc_atomic_apply_metadata_operations(static_cast<RcComm*>(conn), atomic_ops.c_str(), &output);

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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_query(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    //
    // Extract the Bearer token from the Authorization header.
    //

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    auto pos = iter->value().find("Bearer ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string bearer_token{iter->value().substr(pos + 7)};
    boost::trim(bearer_token);
    fmt::print("{}: Bearer token: [{}]\n", __func__, bearer_token);

    // Verify the bearer token is known to the server. If not, return an error.
    {
        const auto iter = authenticated_client_info.find(bearer_token);
        if (iter == std::end(authenticated_client_info)) {
            fmt::print("{}: Could not find bearer token matching [{}].\n", __func__, bearer_token);
            http::response<http::string_body> res{http::status::unauthorized, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }
    }

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        fmt::print("{}: Missing [op] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    if (op_iter->second == "execute") {
        const auto query_iter = url.query.find("query");
        if (query_iter == std::end(url.query)) {
            // TODO Required
        }

        const auto query_type_iter = url.query.find("query-type");
        if (query_type_iter != std::end(url.query)) {
        }

        // TODO GenQuery2 is definitely the right answer for this simply because of
        // pagination features such as OFFSET and LIMIT. We can make that a runtime
        // configuration option.

        try {
            irods::experimental::client_connection conn;

            json::array_t row;
            json::array_t rows;

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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "list_genquery_columns") {
        // TODO These are likely defined in a C array.
        // GenQuery2 doesn't expose these. Perhaps the REST API doesn't need to either.
    }
    else if (op_iter->second == "list_specific_queries") {
        // TODO Look at iquest's implementation.
    }
    else {
        fmt::print("{}: Invalid operator [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_resources(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    //
    // Extract the Bearer token from the Authorization header.
    //

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    auto pos = iter->value().find("Bearer ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string bearer_token{iter->value().substr(pos + 7)};
    boost::trim(bearer_token);
    fmt::print("{}: Bearer token: [{}]\n", __func__, bearer_token);

    // Verify the bearer token is known to the server. If not, return an error.
    {
        const auto iter = authenticated_client_info.find(bearer_token);
        if (iter == std::end(authenticated_client_info)) {
            fmt::print("{}: Could not find bearer token matching [{}].\n", __func__, bearer_token);
            http::response<http::string_body> res{http::status::unauthorized, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }
    }

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        fmt::print("{}: Missing [op] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    namespace ia = irods::experimental::administration;

    if (op_iter->second == "create") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        const auto type_iter = url.query.find("type");
        if (type_iter == std::end(url.query)) {
            fmt::print("{}: Missing [type] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            ia::resource_registration_info resc_info;
            resc_info.resource_name = name_iter->second;
            resc_info.resource_type = type_iter->second;

            const auto host_iter = url.query.find("host");
            if (host_iter != std::end(url.query)) {
                resc_info.host_name = host_iter->second;
            }

            const auto vault_path_iter = url.query.find("vault-path");
            if (vault_path_iter != std::end(url.query)) {
                resc_info.vault_path = vault_path_iter->second;
            }

            const auto ctx_iter = url.query.find("context");
            if (ctx_iter != std::end(url.query)) {
                resc_info.context_string = ctx_iter->second;
            }

            irods::experimental::client_connection conn;
            ia::client::add_resource(conn, resc_info);

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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::remove_resource(conn, name_iter->second);

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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "modify") {
        // TODO
    }
    else if (op_iter->second == "stat") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            irods::experimental::client_connection conn;

            json::object_t info;
            bool exists = false;

            if (const auto resc = ia::client::resource_info(conn, name_iter->second); resc) {
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "add_child") {
        const auto parent_name_iter = url.query.find("parent-name");
        if (parent_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        const auto child_name_iter = url.query.find("child-name");
        if (child_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            irods::experimental::client_connection conn;

            const auto ctx_iter = url.query.find("context");
            if (ctx_iter != std::end(url.query)) {
                ia::client::add_child_resource(conn, parent_name_iter->second, child_name_iter->second, ctx_iter->second);
            }
            else {
                ia::client::add_child_resource(conn, parent_name_iter->second, child_name_iter->second);
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove_child") {
        const auto parent_name_iter = url.query.find("parent-name");
        if (parent_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        const auto child_name_iter = url.query.find("child-name");
        if (child_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::remove_child_resource(conn, parent_name_iter->second, child_name_iter->second);

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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "rebalance") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [name] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::rebalance_resource(conn, name_iter->second);

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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operator [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_rules(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        fmt::print("{}: Incorrect HTTP method.\n", __func__);
        http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    //
    // Extract the Bearer token from the Authorization header.
    //

    const auto& hdrs = _req.base();
    const auto iter = hdrs.find("authorization");
    if (iter == std::end(hdrs)) {
        fmt::print("{}: Missing authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    fmt::print("{}: Authorization value: [{}]\n", __func__, iter->value());

    auto pos = iter->value().find("Bearer ");
    if (std::string_view::npos == pos) {
        fmt::print("{}: Malformed authorization header.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    std::string bearer_token{iter->value().substr(pos + 7)};
    boost::trim(bearer_token);
    fmt::print("{}: Bearer token: [{}]\n", __func__, bearer_token);

    // Verify the bearer token is known to the server. If not, return an error.
    const std::string* username{};
    {
        const auto iter = authenticated_client_info.find(bearer_token);
        if (iter == std::end(authenticated_client_info)) {
            fmt::print("{}: Could not find bearer token matching [{}].\n", __func__, bearer_token);
            http::response<http::string_body> res{http::status::unauthorized, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        username = &iter->second.username;
    }

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        fmt::print("{}: Missing [op] parameter.\n", __func__);
        http::response<http::string_body> res{http::status::bad_request, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::content_length, "0");
        res.keep_alive(_req.keep_alive());
        return res;
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    if (op_iter->second == "execute") {
        // TODO Wrap all of this in a try-catch block.

        ExecMyRuleInp input{};

        std::strncpy(input.myRule, "@external rule { writeLine('stdout', 'DID IT'); }", sizeof(ExecMyRuleInp::myRule));

        irods::at_scope_exit clear_kvp{[&input] {
            clearKeyVal(&input.condInput);
            clearMsParamArray(input.inpParamArray, 0); // 0 -> do not free external structure.
        }};

        const auto rep_instance_iter = url.query.find("rep-instance");
        if (rep_instance_iter != std::end(url.query)) {
            addKeyVal(&input.condInput, irods::KW_CFG_INSTANCE_NAME, rep_instance_iter->second.c_str());
        }

        MsParamArray param_array{};
        //MsParamArray* mspa_ptr = &param_array;
        input.inpParamArray = &param_array;
        std::strncpy(input.outParamDesc, "ruleExecOut", sizeof(input.outParamDesc));

        MsParamArray* out_param_array{};

        irods::experimental::client_connection conn;

        if (const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array); ec < 0) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }}
            }.dump();
        }
        else {
            json stdout_output;
            json stderr_output;

            if (auto* msp = getMsParamByType(out_param_array, ExecCmdOut_PI); msp) {
                if (const auto* exec_out = static_cast<ExecCmdOut*>(msp->inOutStruct); exec_out) {
                    if (exec_out->stdoutBuf.buf) {
                        stdout_output = static_cast<const char*>(exec_out->stdoutBuf.buf);
                        fmt::print("{}: stdout_output = [{}]\n", __func__, stdout_output.get_ref<const std::string&>());
                    }

                    if (exec_out->stderrBuf.buf) {
                        stderr_output = static_cast<const char*>(exec_out->stderrBuf.buf);
                        fmt::print("{}: stderr_output = [{}]\n", __func__, stderr_output.get_ref<const std::string&>());
                    }
                }
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
                {"stdout", stdout_output},
                {"stderr", stderr_output}
            }.dump();
        }
    }
    else if (op_iter->second == "remove_delay_rule") {
        const auto rule_id_iter = url.query.find("rule-id");
        if (rule_id_iter == std::end(url.query)) {
            fmt::print("{}: Missing [rule_id] parameter.\n", __func__);
            http::response<http::string_body> res{http::status::method_not_allowed, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

        try {
            irods::experimental::client_connection conn;

            RuleExecDeleteInput input{};
            std::strncpy(input.ruleExecId, rule_id_iter->second.c_str(), sizeof(RuleExecDeleteInput::ruleExecId));

            const auto ec = rcRuleExecDel(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "modify_delay_rule") {
    }
    else if (op_iter->second == "list_rule_engines") {
        ExecMyRuleInp input{};

        irods::at_scope_exit clear_kvp{[&input] {
            clearKeyVal(&input.condInput);
            clearMsParamArray(input.inpParamArray, 0); // 0 -> do not free external structure.
        }};

        addKeyVal(&input.condInput, AVAILABLE_KW, "");

        MsParamArray param_array{};
        //MsParamArray* mspa_ptr = &param_array;
        input.inpParamArray = &param_array;

        MsParamArray* out_param_array{};

        irods::experimental::client_connection conn;

        if (const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array); ec < 0) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }}
            }.dump();
        }
        else {
            json stdout_output;
            json stderr_output;

            if (auto* msp = getMsParamByType(out_param_array, ExecCmdOut_PI); msp) {
                if (const auto* exec_out = static_cast<ExecCmdOut*>(msp->inOutStruct); exec_out) {
                    if (exec_out->stdoutBuf.buf) {
                        stdout_output = static_cast<const char*>(exec_out->stdoutBuf.buf);
                        fmt::print("{}: stdout_output = [{}]\n", __func__, stdout_output.get_ref<const std::string&>());
                    }

                    if (exec_out->stderrBuf.buf) {
                        stderr_output = static_cast<const char*>(exec_out->stderrBuf.buf);
                        fmt::print("{}: stderr_output = [{}]\n", __func__, stderr_output.get_ref<const std::string&>());
                    }
                }
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
                {"stdout", stdout_output},
                {"stderr", stderr_output}
            }.dump();
        }
    }
    else if (op_iter->second == "list_delay_rules") {
        const auto all_rules_iter = url.query.find("all-rules");
        if (all_rules_iter == std::end(url.query)) {
            // TODO
        }

        try {
            irods::experimental::client_connection conn;

            const auto gql = fmt::format(
                "select "
                "RULE_EXEC_ID, "
                "RULE_EXEC_NAME, "
                "RULE_EXEC_REI_FILE_PATH, "
                "RULE_EXEC_USER_NAME, "
                "RULE_EXEC_ADDRESS, "
                "RULE_EXEC_TIME, "
                "RULE_EXEC_FREQUENCY, "
                "RULE_EXEC_PRIORITY, "
                "RULE_EXEC_ESTIMATED_EXE_TIME, "
                "RULE_EXEC_NOTIFICATION_ADDR, "
                "RULE_EXEC_LAST_EXE_TIME, "
                "RULE_EXEC_STATUS, "
                "RULE_EXEC_CONTEXT "
                "where RULE_EXEC_USER_NAME = '{}'",
                *username);

            json::array_t row;
            json::array_t rows;

            for (auto&& r : irods::query{static_cast<RcComm*>(conn), gql}) {
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

const std::unordered_map<std::string_view, request_handler> req_handlers{
    {"/irods-rest/0.9.5/auth",         handle_auth},
    {"/irods-rest/0.9.5/collections",  handle_collections},
    //{"/irods-rest/0.9.5/config",       "/config"},
    {"/irods-rest/0.9.5/data-objects", handle_data_objects},
    {"/irods-rest/0.9.5/metadata",     handle_metadata},
    {"/irods-rest/0.9.5/query",        handle_query},
    {"/irods-rest/0.9.5/resources",    handle_resources},
    {"/irods-rest/0.9.5/rules",        handle_rules},
    //{"/irods-rest/0.9.5/tickets",      "/tickets"},
    //{"/irods-rest/0.9.5/users",        "/users"},
    //{"/irods-rest/0.9.5/groups",       "/groups"},
    //{"/irods-rest/0.9.5/zones",        "/zones"}
};

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send)
{
    // Print the headers.
    for (auto&& h : req.base()) {
        fmt::print(fmt::runtime("header: ({}, {})\n"), h.name_string(), h.value());
    }

    // Print the components of the request URL.
    fmt::print("method            : {}\n", req.method_string());
    fmt::print("version           : {}\n", req.version());
    fmt::print("target            : {}\n", req.target());
    fmt::print("keep alive        : {}\n", req.keep_alive());
    fmt::print("has content length: {}\n", req.has_content_length());
    fmt::print("chunked           : {}\n", req.chunked());
    fmt::print("needs eof         : {}\n", req.need_eof());

    const auto url = parse_url(req);
    const auto iter = req_handlers.find(url.path);

    if (iter == std::end(req_handlers)) {
        // TODO Invalid path (send bad request error code?).
        http::response<http::empty_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(req.keep_alive());
        send(std::move(res));
    }

    send((iter->second)(req));
}

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session>
{
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self)
            : self_(self)
        {
        }

        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg) const
        {
            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.stream_,
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    self_.shared_from_this(),
                    sp->need_eof()));
        }
    };

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

public:
    // Take ownership of the stream
    session(tcp::socket&& socket)
        : stream_(std::move(socket))
        , lambda_(*this)
    {
    }

    // Start the asynchronous operation
    void
    run()
    {
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session. Although not strictly necessary
        // for single-threaded contexts, this example code is written to be
        // thread-safe by default.
        net::dispatch(stream_.get_executor(),
                      beast::bind_front_handler(
                          &session::do_read,
                          shared_from_this()));
    }

    void
    do_read()
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return do_close();

        if(ec)
            return fail(ec, "read");

        // Send the response
        handle_request(std::move(req_), lambda_);
    }

    void
    on_write(
        bool close,
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }

    void
    do_close()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;

public:
    listener(net::io_context& ioc, tcp::endpoint endpoint)
        : ioc_(ioc)
        , acceptor_(net::make_strand(ioc))
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (ec) {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }

        // Create the session and run it
        std::make_shared<session>(std::move(socket))->run();

        // Accept another connection
        do_accept();
    }
};

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    // Check command line arguments.
    if (argc != 4) {
        std::cerr <<
            "Usage: http-server-async <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    http-server-async 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }

    load_client_api_plugins();

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[3]));

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // Create and launch a listening port
    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    return EXIT_SUCCESS;
}
