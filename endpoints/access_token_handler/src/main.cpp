#include "irods/private/http_api/handlers.hpp"
#include "irods/private/http_api/common.hpp"
#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/process_stash.hpp"
#include "irods/private/http_api/session.hpp"
#include "irods/private/http_api/transport.hpp"
#include "irods/private/http_api/version.hpp"

#include <irods/base64.hpp>
#include <irods/check_auth_credentials.h>
#include <irods/client_connection.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcConnect.h>
#include <irods/user_administration.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/url/parse.hpp>

#include <iterator>
#include <nlohmann/json.hpp>

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <fmt/core.h>

#include <curl/curl.h>
#include <curl/urlapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <chrono>

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
// clang-format on

using body_arguments = std::unordered_map<std::string, std::string>;

namespace irods::http::handler
{
    auto make_json_response(boost::beast::http::status status, const nlohmann::json& content) -> response_type {
        response_type res{status, 11};
        res.set(field_type::server, irods::http::version::server_name);
        res.set(field_type::content_type, "application/json");
        res.keep_alive(false);
        res.body() = content.dump();
        res.prepare_payload();

        return res;
    }

    bool is_token_expired(const nlohmann::json& decoded_token) {
        auto it = decoded_token.find("exp");
        if (it != decoded_token.end() && it.value().is_number()) {
            auto expiration_timestamp = it.value().get<int64_t>();
            auto current_time = std::chrono::system_clock::now();
            auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(current_time.time_since_epoch()).count();
            return current_timestamp >= expiration_timestamp;
        }
        // If expiration claim is missing or invalid, we need to throw an error as well
        return true;
    }

    auto validate_and_process_access_token(std::string_view _access_token) -> nlohmann::json
    {
        const std::string jwt_token{_access_token};
        auto decoded_token{jwt::decode<jwt::traits::nlohmann_json>(jwt_token).get_payload_json()};

        const auto& irods_claim_name{irods::http::globals::oidc_configuration()
            .at("irods_user_claim")
            .get_ref<const std::string&>()};
        
        if (!decoded_token.contains(irods_claim_name)) {
            const auto user{
                decoded_token.contains("preferred_username")
                    ? decoded_token.at("preferred_username").get<const std::string>()
                    : ""};

            log::error("No irods user associated with authenticated user [{}].", user);
            return {{"error", "No irods user associated with authenticated user"}};
        }

        const auto provider_url{
			irods::http::globals::oidc_endpoint_configuration().at("provider_url").get_ref<const std::string&>()};

        // Issuer Verification
        const auto expected_issuer = provider_url;
        const auto& decoded_issuer = decoded_token["iss"];
        log::info("Expected Issuer: {}", expected_issuer);
        log::info("Decoded Issuer: {}", decoded_issuer);
        if (!decoded_issuer.is_string() || decoded_issuer.get<std::string>() != expected_issuer) {
            log::error("Issuer verification failed.");
            return {{"error", "Issuer verification failed"}};
        }

        // Token Expiration Verification
        if (is_token_expired(decoded_token)) {
            log::error("Token has expired.");
            return {{"error", "Token has expired or its expiration time is missing or invalid"}};
        }

        // Get irods username from the token
        const std::string& irods_name{decoded_token.at(irods_claim_name).get_ref<const std::string&>()};

        static const auto seconds =
            irods::http::globals::configuration()
                .at(nlohmann::json::json_pointer{
                    "/http_server/authentication/openid_connect/timeout_in_seconds"})
                .get<int>();

        // Generates a bearer token for the authenticated client to match 
        // the struct currently used in resolve_client_identity function to cast the info extracted from token 
        //  (struct authenticated_client_info)
        // that is the validation filter for any endpoint fetching at the moment
        auto bearer_token = irods::http::process_stash::insert(authenticated_client_info{
            .auth_scheme = authorization_scheme::basic,
            .username = std::move(irods_name),
            .expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

        // Return success response with the unique identifier to be used from client
        // for the next endpoints fetching
        return {{"success", true}, {"bearer_token", bearer_token}};
    }


    /*
        Endpoint handler for validating access tokens.
        This function is invoked when a POST request is made to the "/validate-token" endpoint.
        It validates the access token provided in the Authorization header,
        processes it, and returns a response containing a bearer token if the token is valid.
        If the token is invalid or missing, it returns appropriate error responses.

        Main Steps:
        1. Extract the access token from the Authorization header.
        2. Decode and verify the access token using JWT.
        3. Validate the token issuer and expiration time.
        4. If validation succeeds, generate a new bearer token.
        5. Return a success response with the generated bearer token.

        Response (Success):
        - Status Code: 200 OK
        - Body: JSON object containing the following fields:
            - "success": true
            - "bearer_token": The newly generated bearer token for further authentication.
    */
    IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(access_token_handler)
    {
        log::debug("Handling request to access_token_handler");
        if (_req.method() == boost::beast::http::verb::post) {
            const auto auth_header_iter = _req.base().find(boost::beast::http::field::authorization);
            if (auth_header_iter == _req.base().end()) {
                log::error("Authorization header missing.");
                fail(status_type::unauthorized, "Authorization header missing");
                return; 
            }

            const auto& auth_header_value = auth_header_iter->value();

           // Check if the authorization method is Bearer
            static const std::string bearer_prefix = "Bearer ";
            if (auth_header_value.size() <= bearer_prefix.size() ||
                auth_header_value.substr(0, bearer_prefix.size()) != bearer_prefix) {
                log::error("Incorrect Authorization Method");
                fail(status_type::unauthorized, "Incorrect authorization method");
                return;
            }

            const std::string access_token = auth_header_value.substr(bearer_prefix.size());

            // Process and validate the access token received from the client
            const auto response = validate_and_process_access_token(access_token);

            _sess_ptr->send(make_json_response(status_type::ok, response));
        }
        else {
            log::error("HTTP method not supported.");
            fail(status_type::method_not_allowed, "HTTP method not supported");
        }
    }

} // namespace irods::http::handler
