#ifndef IRODS_HTTP_API_OPENID_HPP
#define IRODS_HTTP_API_OPENID_HPP

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>

#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/url/url_view.hpp>

#include <optional>
#include <string>

namespace irods::http::openid
{
	auto create_oidc_request(boost::urls::url_view _url)
		-> boost::beast::http::request<boost::beast::http::string_body>;

	auto validate_using_introspection_endpoint(const std::string& _bearer_token) -> std::optional<nlohmann::json>;

	auto validate_using_local_validation(const jwt::decoded_jwt<jwt::traits::nlohmann_json>& _jwt)
		-> std::optional<nlohmann::json>;
} //namespace irods::http::openid

#endif // IRODS_HTTP_API_OPENID_HPP
