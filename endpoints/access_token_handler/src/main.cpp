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

// clang-format off
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace net   = boost::asio;  // from <boost/asio.hpp>
// clang-format on

using body_arguments = std::unordered_map<std::string, std::string>;

namespace irods::http::handler
{
    auto handle_access_token(std::string_view _access_token) -> nlohmann::json
    {
        // Extract the access token
        const std::string jwt_token{_access_token};

        // Decode the JWT token
        auto decoded_token{jwt::decode<jwt::traits::nlohmann_json>(jwt_token).get_payload_json()};

        // Verify 'irods_username' exists in the token claims
        const auto& irods_claim_name{irods::http::globals::oidc_configuration()
            .at("irods_user_claim")
            .get_ref<const std::string&>()};
                                         
        if (!decoded_token.contains(irods_claim_name)) {
						const auto user{
                decoded_token.contains("preferred_username")
                    ? decoded_token.at("preferred_username").get<const std::string>()
                    : ""};

            log::error("{}: No irods user associated with authenticated user [{}].", fn, user);
            return _sess_ptr->send(fail(status_type::bad_request));
        }

        // Get irods username from the token
		const std::string& irods_name{decoded_token.at(irods_claim_name).get_ref<const std::string&>()};

        static const auto seconds =
            irods::http::globals::configuration()
                .at(nlohmann::json::json_pointer{
                    "/http_server/authentication/openid_connect/timeout_in_seconds"})
                .get<int>();

        auto bearer_token = irods::http::process_stash::insert(authenticated_client_info{
            .auth_scheme = authorization_scheme::basic,
            .username = std::move(irods_name),
            .expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}});

        // Return success response with the unique identifier to be used for next endpoint fetching
        return {{"success", true}, {"bearer_token", bearer_token}};
    }

    IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(access_token_handler)
    {
        log::debug("Handling request to access_token_handler");
        if (_req.method() == boost::beast::http::verb::post) {
            // Check for Authorization header
            const auto auth_header_iter = _req.base().find(boost::beast::http::field::authorization);
            if (auth_header_iter == _req.base().end()) {
                log::error("Authorization header missing.");
                return _sess_ptr->send(fail(status_type::unauthorized));
            }

            // Extract the authorization value
            const auto& auth_header_value = auth_header_iter->value();

            // Check if the authorization method is Bearer
            static const std::string bearer_prefix = "Bearer ";
            // if (auth_header_value.size() <= bearer_prefix.size() ||
            //     !jwt::algorithm::starts_with(auth_header_value, bearer_prefix)) {
            //     log::error("Invalid authorization method.");
            //     return _sess_ptr->send(fail(status_type::unauthorized));
            // }

            // Extract the access token
            const std::string access_token = auth_header_value.substr(bearer_prefix.size());

            // Process the access token
            const auto response = handle_access_token(access_token);

            // Create and send the response
            response_type res_rep{status_type::ok, _req.version()};
            res_rep.set(field_type::server, irods::http::version::server_name);
            res_rep.set(field_type::content_type, "application/json");
            res_rep.keep_alive(_req.keep_alive());
            res_rep.body() = response.dump();
            res_rep.prepare_payload();

            return _sess_ptr->send(std::move(res_rep));
        }
        else {
            log::error("HTTP method not supported.");
            return _sess_ptr->send(fail(status_type::method_not_allowed));
        }
    }
} // namespace irods::http::handler
