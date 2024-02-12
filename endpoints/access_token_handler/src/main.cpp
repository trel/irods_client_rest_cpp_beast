#include "irods/private/http_api/handlers.hpp"
#include "irods/private/http_api/common.hpp"
#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/process_stash.hpp"
#include "irods/private/http_api/session.hpp"
#include "irods/private/http_api/transport.hpp"
#include "irods/private/http_api/version.hpp"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>

using namespace irods::http;

namespace irods::http::handler
{
    auto handle_access_token(std::string_view _access_token) -> nlohmann::json
    {
        // Decode and validate the access token
        jwt::verifier<nlohmann::json, jwt::default_clock, jwt::default_validator<nlohmann::json>> verifier;
        auto decoded_token = jwt::decode<nlohmann::json>(_access_token, verifier);

        // Verify 'irods_username' exists in the token claims
        const auto& irods_claim_name{irods::http::globals::oidc_configuration()
                                         .at("irods_user_claim")
                                         .get_ref<const std::string&>()};
                                         
        if (!decoded_token.contains(irods_claim_name)) {
            const auto user{
                decoded_token.contains("preferred_username")
                    ? decoded_token.at("preferred_username").get<const std::string>()
                    : ""};

            log::error("No irods user associated with authenticated user [{}].", user);
            return {{"error", "No irods user associated with the token"}};
        }

        // Get irods username from the token
        const std::string& irods_name{decoded_token.at(irods_claim_name).get_ref<const std::string&>()};

        // static const auto seconds =
		// 				irods::http::globals::configuration()
		// 					.at(nlohmann::json::json_pointer{
		// 						"/http_server/authentication/openid_connect/timeout_in_seconds"})
		// 					.get<int>();

        auto bearer_token = irods::http::process_stash::insert(authenticated_client_info{
							.auth_scheme = authorization_scheme::basic,
							.username = std::move(irods_name),
							.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{6000}});


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
            if (auth_header_value.size() <= bearer_prefix.size() ||
                !boost::algorithm::starts_with(auth_header_value, bearer_prefix)) {
                log::error("Invalid authorization method.");
                return _sess_ptr->send(fail(status_type::unauthorized));
            }

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
