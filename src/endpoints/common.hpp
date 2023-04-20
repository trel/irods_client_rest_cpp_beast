#ifndef IRODS_HTTP_API_ENDPOINT_COMMON_HPP
#define IRODS_HTTP_API_ENDPOINT_COMMON_HPP

#include "log.hpp"

#include <irods/process_stash.hpp>

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
    // clang-format off
    using field_type    = boost::beast::http::field;
    using request_type  = boost::beast::http::request<boost::beast::http::string_body>;
    using response_type = boost::beast::http::response<boost::beast::http::string_body>;
    using status_type   = boost::beast::http::status;
    using verb_type     = boost::beast::http::verb;
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
        _response.set(boost::beast::http::field::server, "irods-http"); // TODO Should be defined by CMakeLists.txt
        _response.set(boost::beast::http::field::content_type, "text/plain"); // TODO
        _response.set(boost::beast::http::field::content_length, "0");
        _response.body() = _error_msg;
        _response.prepare_payload();
        return _response;
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
} // namespace irods

#endif // IRODS_HTTP_API_ENDPOINT_COMMON_HPP
