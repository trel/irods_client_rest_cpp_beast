//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP server, asynchronous
//
//------------------------------------------------------------------------------

#include <irods/base64.hpp>
#include <irods/client_connection.hpp>
#include <irods/filesystem.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/rcConnect.h>
#include <irods/rodsClient.h>
#include <irods/rodsErrorTable.h>

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
        fmt::print("{}: Incorrect HTTP method for authentication.\n", __func__);
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
        fmt::print("{}: Incorrect HTTP method for authentication.\n", __func__);
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

            const auto no_trash_iter = url.query.find("no_trash");
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
        const auto new_lpath_iter = url.query.find("new_lpath");
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
    else if (op_iter->second == "set_permission") {
        const auto entity_name_iter = url.query.find("entity_name");
        if (entity_name_iter == std::end(url.query)) {
            fmt::print("{}: Missing [entity_name] parameter.\n", __func__);
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
            res.result(http::status::bad_request);
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

            const auto to_string = [](const fs::perms _p)
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

            json perms;
            for (auto&& ep : status.permissions()) {
                perms.push_back(json{
                    {"name", ep.name},
                    {"zone", ep.zone},
                    {"type", ep.type},
                    {"perm", to_string(ep.prms)},
                });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"type", status.type()},
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
    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());
    res.body() ="";
    res.prepare_payload();
    return res;
}

auto handle_metadata(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());
    res.body() ="";
    res.prepare_payload();
    return res;
}

auto handle_query(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get) {
        fmt::print("{}: Incorrect HTTP method for authentication.\n", __func__);
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

        const auto query_type_iter = url.query.find("query_type");
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
    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());
    res.body() ="";
    res.prepare_payload();
    return res;
}

// This will eventually become a mapping of strings to functions.
// The incoming requests will be passed to the functions for further processing.
const std::unordered_map<std::string_view, request_handler> req_handlers{
    {"/irods-rest/0.9.5/auth",         handle_auth},
    {"/irods-rest/0.9.5/collections",  handle_collections},
    //{"/irods-rest/0.9.5/config",       "/config"},
    {"/irods-rest/0.9.5/data-objects", handle_data_objects},
    {"/irods-rest/0.9.5/metadata",     handle_metadata},
    {"/irods-rest/0.9.5/query",        handle_query},
    {"/irods-rest/0.9.5/resources",    handle_resources},
    //{"/irods-rest/0.9.5/rules",        "/rules"},
    //{"/irods-rest/0.9.5/tickets",      "/tickets"},
    //{"/irods-rest/0.9.5/users",        "/users"},
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
    // TODO Use libcurl - curl_easy_unescape to decode URL (at least until Boost.URL is available).
    // See https://curl.se/libcurl/c/curl_easy_unescape.html.
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
