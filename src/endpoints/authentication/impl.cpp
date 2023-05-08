#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"

#include <irods/base64.hpp>
#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/process_stash.hpp>
#include <irods/rcConnect.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace irods::http::handler
{
    auto authentication(session_pointer_type _sess_ptr, request_type& _req) -> void
    {
        if (_req.method() != boost::beast::http::verb::post) {
            return _sess_ptr->send(fail(status_type::method_not_allowed));
        }

        const auto& hdrs = _req.base();
        const auto iter = hdrs.find("authorization");
        if (iter == std::end(hdrs)) {
            return _sess_ptr->send(fail(status_type::bad_request));
        }

        log::debug("{}: Authorization value: [{}]", __func__, iter->value());

        //
        // TODO Here is where we determine what form of authentication to perform (e.g. Basic or OIDC).
        //

        const auto pos = iter->value().find("Basic ");
        if (std::string_view::npos == pos) {
            return _sess_ptr->send(fail(status_type::bad_request));
        }

        constexpr auto basic_auth_scheme_prefix_size = 6;
        std::string authorization{iter->value().substr(pos + basic_auth_scheme_prefix_size)};
        boost::trim(authorization);
        log::debug("{}: Authorization value (trimmed): [{}]", __func__, authorization);

        constexpr auto max_creds_size = 128;
        unsigned long size = max_creds_size;
        std::vector<std::uint8_t> creds(size);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto ec = irods::base64_decode(reinterpret_cast<unsigned char*>(authorization.data()), authorization.size(), creds.data(), &size);
        log::debug("{}: base64 error code         = [{}]", __func__, ec);
        log::debug("{}: base64 decoded size       = [{}]", __func__, size);

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        std::string_view sv{reinterpret_cast<char*>(creds.data()), size}; 
        log::debug("{}: base64 decode credentials = [{}]", __func__, sv);

        const auto colon = sv.find(':');
        if (colon == std::string_view::npos) {
            return _sess_ptr->send(fail(status_type::unauthorized));
        }

        std::string username{sv.substr(0, colon)};
        std::string password{sv.substr(colon + 1)};
        log::debug("{}: username = [{}]", __func__, username);
        log::debug("{}: password = [{}]", __func__, password);

        bool login_successful = false;

        try {
            const auto& svr = irods::http::globals::config->at("irods_client");
            const auto& host = svr.at("host").get_ref<const std::string&>();
            const auto port = svr.at("port").get<std::uint16_t>();
            const auto& zone = svr.at("zone").get_ref<const std::string&>();

            irods::experimental::client_connection conn{
                irods::experimental::defer_authentication, host, port, username, zone};

            login_successful = (clientLoginWithPassword(static_cast<RcComm*>(conn), password.data()) == 0);
        }
        catch (const irods::exception& e) {
            log::error(e.client_display_what());
        }

        if (!login_successful) {
            return _sess_ptr->send(fail(status_type::unauthorized));
        }

        const auto seconds = irods::http::globals::config->at(nlohmann::json::json_pointer{"/http_server/authentication/basic/timeout_in_seconds"}).get<int>();
        auto bearer_token = irods::process_stash::insert(authenticated_client_info{
            .auth_scheme = authorization_scheme::basic,
            .username = std::move(username),
            .password = std::move(password),
            .expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{seconds}
        });

        response_type res{status_type::ok, _req.version()};
        res.set(field_type::server, BOOST_BEAST_VERSION_STRING);
        res.set(field_type::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());
        res.body() = std::move(bearer_token);
        res.prepare_payload();

        return _sess_ptr->send(std::move(res));
    } // authentication
} // namespace irods::http::endpoint
