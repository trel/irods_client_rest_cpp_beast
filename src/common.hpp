#ifndef IRODS_HTTP_API_ENDPOINT_COMMON_HPP
#define IRODS_HTTP_API_ENDPOINT_COMMON_HPP

#include "globals.hpp"
#include "log.hpp"
#include "version.hpp"

#include <irods/connection_pool.hpp>
#include <irods/filesystem/object_status.hpp>
#include <irods/filesystem/permissions.hpp>
#include <irods/irods_exception.hpp>
#include <irods/process_stash.hpp>
#include <irods/rodsErrorTable.h>
#include <irods/switch_user.h>

#include <boost/any.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/algorithm/string.hpp>

#include <curl/curl.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace irods::http
{
    class session;

    // clang-format off
    using field_type    = boost::beast::http::field;
    using request_type  = boost::beast::http::request<boost::beast::http::string_body>;
    using response_type = boost::beast::http::response<boost::beast::http::string_body>;
    using status_type   = boost::beast::http::status;
    using verb_type     = boost::beast::http::verb;

    using session_pointer_type = std::shared_ptr<irods::http::session>;
    using request_handler_type = void(*)(session_pointer_type, const request_type&);

    using request_handler_map_type = std::unordered_map<std::string_view, request_handler_type>;
    // clang-format on

    enum class authorization_scheme
    {
        basic = 0,
        open_id_connect
    }; // enum class authorization_scheme

    struct authenticated_client_info
    {
        authorization_scheme auth_scheme;
        std::string username;
        std::string password; // TODO Probably not needed.
        // TODO Store an expiration timestamp here. Post discush: let it expire and send reauth code to client.
        // Perhaps a purge timestamp as well. This is an optimization situation.
    }; // struct authenticated_client_info

    inline auto fail(response_type& _response, status_type _status, const std::string_view _error_msg) -> response_type
    {
        _response.result(_status);
        _response.set(field_type::server, version::server_name);
        _response.set(field_type::content_type, "application/json");
        //_response.set(boost::beast::http::field::content_length, "0");
        _response.body() = _error_msg;
        _response.prepare_payload();
        return _response;
    } // fail

    inline auto fail(response_type& _response, status_type _status) -> response_type
    {
        return fail(_response, _status, "");
    } // fail

    inline auto fail(status_type _status, const std::string_view _error_msg) -> response_type
    {
        response_type r{_status, 11};
        return fail(r, _status, _error_msg);
    } // fail

    inline auto fail(status_type _status) -> response_type
    {
        response_type r{_status, 11};
        return fail(r, _status, "");
    } // fail

    inline auto decode(const std::string_view _v) -> std::string
    {
        std::string result;
        int decoded_length = -1;

        if (auto* decoded = curl_easy_unescape(nullptr, _v.data(), _v.size(), &decoded_length); decoded) {
            std::unique_ptr<char, void(*)(void*)> s{decoded, curl_free};
            result.assign(decoded, decoded_length);
        }
        else {
            result.assign(_v);
        }

        return result;
    } // decode

    // TODO Create a better name.
    inline auto to_argument_list(const std::string_view& _urlencoded_string) -> std::unordered_map<std::string, std::string>
    {
        if (_urlencoded_string.empty()) {
            return {};
        }

        std::unordered_map<std::string, std::string> kvps;

        std::vector<std::string> tokens;
        boost::split(tokens, _urlencoded_string, boost::is_any_of("&"));

        std::vector<std::string> kvp;

        for (auto&& t : tokens) {
            boost::split(kvp, t, boost::is_any_of("="));

            if (kvp.size() == 2) {
                kvps.insert_or_assign(std::move(kvp[0]), decode(kvp[1]));
            }
            else if (kvp.size() == 1) {
                kvps.insert_or_assign(std::move(kvp[0]), "");
            }

            kvp.clear();
        }

        return kvps;
    } // to_argument_list

    inline auto get_url_path(const std::string& _url) -> std::optional<std::string>
    {
        namespace log = irods::http::log;

        std::unique_ptr<CURLU, void(*)(CURLU*)> curl{curl_url(), curl_url_cleanup};

        if (!curl) {
            log::error("{}: Could not initialize libcurl.", __func__);
            return std::nullopt;
        }

        if (const auto ec = curl_url_set(curl.get(), CURLUPART_URL, _url.c_str(), 0); ec) {
            log::error("{}: curl_url_set error: {}", __func__, ec);
            return std::nullopt;
        }

        using curl_string = std::unique_ptr<char, void(*)(void*)>;

        // Extract the path.
        // This is what we use to route requests to the various endpoints.
        char* path{};
        if (const auto ec = curl_url_get(curl.get(), CURLUPART_PATH, &path, 0); ec == 0) {
            curl_string cpath{path, curl_free};
            return path;
        }
        else {
            log::error("{}: curl_url_get(CURLUPART_PATH) error: {}", __func__, ec);
            return std::nullopt;
        }
    } // get_url_path

    struct url
    {
        std::string path;
        std::unordered_map<std::string, std::string> query;
    };

    inline auto parse_url(const std::string& _url) -> url
    {
        namespace log = irods::http::log;

        std::unique_ptr<CURLU, void(*)(CURLU*)> curl{curl_url(), curl_url_cleanup};

        if (!curl) {
            // TODO Report internal server error.
            log::error("{}: Could not initialize libcurl.", __func__);
        }

        // Include a bogus prefix. We only care about the path and query parts of the URL.
        if (const auto ec = curl_url_set(curl.get(), CURLUPART_URL, _url.c_str(), 0); ec) {
            // TODO Report error.
            log::error("{}: curl_url_set error: {}", __func__, ec);
        }

        url url;

        using curl_string = std::unique_ptr<char, void(*)(void*)>;

        // Extract the path.
        // This is what we use to route requests to the various endpoints.
        char* path{};
        if (const auto ec = curl_url_get(curl.get(), CURLUPART_PATH, &path, 0); ec == 0) {
            curl_string cpath{path, curl_free};
            if (path) {
                url.path = path;
            }
        }
        else {
            // TODO Report error.
            log::error("{}: curl_url_get(CURLUPART_PATH) error: {}", __func__, ec);
        }

        // Extract the query.
        // ChatGPT states that the values in the key value pairs must escape embedded equal signs.
        // This allows the HTTP server to parse the query string correctly. Therefore, we don't have
        // to protect against that case. The client must send the correct URL escaped input.
        char* query{};
        if (const auto ec = curl_url_get(curl.get(), CURLUPART_QUERY, &query, 0); ec == 0) {
            curl_string cs{query, curl_free};
            if (query) {
                url.query = to_argument_list(query);
            }
        }
        else {
            // TODO
            log::error("{}: curl_url_get(CURLUPART_QUERY) error: {}", __func__, ec);
        }

        return url;
    } // parse_url

    inline auto parse_url(const request_type& _req) -> url
    {
        return parse_url(fmt::format("http://ignored{}", _req.target()));
    } // parse_url

    struct client_identity_resolution_result
    {
        std::optional<response_type> response;
        const authenticated_client_info* client_info{};
    };

    inline auto resolve_client_identity(const request_type& _req) -> client_identity_resolution_result
    {
        namespace log = irods::http::log;

        //
        // Extract the Bearer token from the Authorization header.
        //

        const auto& hdrs = _req.base();
        const auto iter = hdrs.find("Authorization");
        if (iter == std::end(hdrs)) {
            log::error("{}: Missing [Authorization] header.", __func__);
            return {.response = fail(status_type::bad_request)};
        }

        log::debug("{}: Authorization value: [{}]", __func__, iter->value());

        auto pos = iter->value().find("Bearer ");
        if (std::string_view::npos == pos) {
            log::debug("{}: Malformed authorization header.", __func__);
            return {.response = fail(status_type::bad_request)};
        }

        std::string bearer_token{iter->value().substr(pos + 7)};
        boost::trim(bearer_token);
        log::debug("{}: Bearer token: [{}]", __func__, bearer_token);

        // Verify the bearer token is known to the server. If not, return an error.
        const auto* object = irods::process_stash::find(bearer_token);
        if (!object) {
            log::error("{}: Could not find bearer token matching [{}].", __func__, bearer_token);
            return {.response = fail(status_type::unauthorized)};
        }

        log::debug("{}: Client is authenticated.", __func__);
        return {.client_info = boost::any_cast<authenticated_client_info>(&*object)};
    } // resolve_client_identity
} // namespace irods::http

namespace irods
{
    template <typename Map>
    auto generate_uuid(const Map& _map) -> std::string
    {
        std::string uuid;
        uuid.reserve(36); // NOLINT(cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers)
        uuid = to_string(boost::uuids::random_generator{}());

        while (_map.find(uuid) != std::end(_map)) {
            uuid = to_string(boost::uuids::random_generator{}());
        }

        return uuid;
    } // generate_uuid

    inline auto to_permission_string(const irods::experimental::filesystem::perms _p) -> const char*
    {
        using irods::experimental::filesystem::perms;

        switch (_p) {
            case perms::null:            return "null";
            case perms::read_metadata:   return "read_metadata";
            case perms::read_object:     return "read_object";
            case perms::read:            return "read_object";
            case perms::create_metadata: return "create_metadata";
            case perms::modify_metadata: return "modify_metadata";
            case perms::delete_metadata: return "delete_metadata";
            case perms::create_object:   return "create_object";
            case perms::modify_object:   return "modify_object";
            case perms::write:           return "modify_object";
            case perms::delete_object:   return "delete_object";
            case perms::own:             return "own";
            default:                     return "?"; // TODO std::unreachable() or __builtin_unreachable()
        }
    } // to_permission_string

    inline auto to_permission_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::perms>
    {
        using irods::experimental::filesystem::perms;

        // clang-format off
        if (_s == "null")            { return perms::null; }
        if (_s == "read_metadata")   { return perms::read_metadata; }
        if (_s == "read_object")     { return perms::read_object; }
        if (_s == "red")             { return perms::read; }
        if (_s == "create_metadata") { return perms::create_metadata; }
        if (_s == "modify_metadata") { return perms::modify_metadata; }
        if (_s == "delete_metadata") { return perms::delete_metadata; }
        if (_s == "create_object")   { return perms::create_object; }
        if (_s == "modify_object")   { return perms::modify_object; }
        if (_s == "write")           { return perms::write; }
        if (_s == "delete_object")   { return perms::delete_object; }
        if (_s == "own")             { return perms::own; }
        // clang-format on

        return std::nullopt;
    } // to_permission_enum

    inline auto to_object_type_string(const irods::experimental::filesystem::object_type _t) -> const char*
    {
        using irods::experimental::filesystem::object_type;

        switch (_t) {
            case object_type::collection:         return "collection";
            case object_type::data_object:        return "data_object";
            case object_type::none:               return "none";
            case object_type::not_found:          return "not_found";
            case object_type::special_collection: return "special_collection";
            case object_type::unknown:            return "unknown";
            default:                              return "?";
        }
    } // to_object_type_string

    inline auto to_object_type_enum(const std::string_view _s) -> std::optional<irods::experimental::filesystem::object_type>
    {
        using irods::experimental::filesystem::object_type;

        // clang-format off
        if (_s == "collection")         { return object_type::collection; }
        if (_s == "data_object")        { return object_type::data_object; }
        if (_s == "none")               { return object_type::none; }
        if (_s == "not_found")          { return object_type::not_found; }
        if (_s == "special_collection") { return object_type::special_collection; }
        if (_s == "unknown")            { return object_type::unknown; }
        // clang-format on

        return std::nullopt;
    } // to_object_type_enum

    // TODO May require the zone name be passed as well for federation?
    inline auto get_connection(const std::string& _username) -> irods::connection_pool::connection_proxy
    {
        namespace log = irods::http::log;

        auto& cp = irods::http::globals::conn_pool;
        auto conn = cp->get_connection();
        const auto& zone = irods::http::globals::config->at("irods_server").at("zone").get_ref<const std::string&>();

        log::trace("{}: Changing identity associated with connection to [{}].", __func__, _username);

        if (const auto ec = rc_switch_user(static_cast<RcComm*>(conn), _username.c_str(), zone.c_str()); ec != 0) {
            irods::http::log::error("{}: rc_switch_user error: {}", __func__, ec);
            THROW(SYS_INTERNAL_ERR, "");
        }

        log::trace("{}: Successfully changed identity associated with connection to [{}].", __func__, _username);

        return conn;
    } // get_connection

    inline auto fail(boost::beast::error_code ec, char const* what) -> void
    {
        irods::http::log::error("{}: {}: {}", __func__, what, ec.message());
    } // fail
} // namespace irods

#endif // IRODS_HTTP_API_ENDPOINT_COMMON_HPP
