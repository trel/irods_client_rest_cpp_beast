#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"

#include <irods/base64.hpp>
#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>
#include <irods/process_stash.hpp>
#include <irods/rcConnect.h>

#include <boost/asio.hpp>
//#include <boost/asio/ip/tcp.hpp> // TODO Remove
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <string>
#include <string_view>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>
// clang-format on

//using tcp = boost::asio::ip::tcp;   // from <boost/asio/ip/tcp.hpp> // TODO Remove

namespace irods::http::handler
{
    auto authentication(const request_type& _req) -> response_type
    {
        if (_req.method() != boost::beast::http::verb::post) {
            return fail(status_type::method_not_allowed);
        }

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

        const auto& hdrs = _req.base();
        const auto iter = hdrs.find("authorization");
        if (iter == std::end(hdrs)) {
            return fail(status_type::bad_request);
        }

        log::debug("{}: Authorization value: [{}]\n", __func__, iter->value());

        //
        // TODO Here is where we determine what form of authentication to perform (e.g. Basic or OIDC).
        //

        const auto pos = iter->value().find("Basic ");
        if (std::string_view::npos == pos) {
            return fail(status_type::bad_request);
        }

        std::string authorization{iter->value().substr(pos + 6)};
        boost::trim(authorization);
        log::debug("{}: Authorization value (trimmed): [{}]\n", __func__, authorization);

        unsigned long size = 128;
        std::vector<std::uint8_t> creds(size); // TODO
        const auto ec = irods::base64_decode((unsigned char*) authorization.data(), authorization.size(), creds.data(), &size); // TODO
        log::debug("{}: base64 error code         = [{}]\n", __func__, ec);
        log::debug("{}: base64 decoded size       = [{}]\n", __func__, size);

        std::string_view sv{(char*) creds.data(), size}; 
        log::debug("{}: base64 decode credentials = [{}]\n", __func__, sv);

        const auto colon = sv.find(':');
        if (colon == std::string_view::npos) {
            return fail(status_type::unauthorized);
        }

        std::string username{sv.substr(0, colon)};
        std::string password{sv.substr(colon + 1)};
        log::debug("{}: username = [{}]\n", __func__, username);
        log::debug("{}: password = [{}]\n", __func__, password);

        bool login_successful = false;

        try {
            irods::experimental::client_connection conn{
                irods::experimental::defer_authentication, "localhost", 1247, username, "tempZone"};

            login_successful = (clientLoginWithPassword(static_cast<RcComm*>(conn), password.data()) == 0);
        }
        catch (const irods::exception& e) {
            log::error(e.client_display_what());
        }

        if (!login_successful) {
            return fail(status_type::unauthorized);
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
        auto bearer_token = irods::process_stash::insert(authenticated_client_info{
            .auth_scheme = authorization_scheme::basic,
            .username = std::move(username),
            .password = std::move(password)
        });

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

        response_type res{status_type::ok, _req.version()};
        res.set(field_type::server, BOOST_BEAST_VERSION_STRING);
        res.set(field_type::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());
        res.body() = std::move(bearer_token);
        res.prepare_payload();

        return res;
    } // authentication
} // namespace irods::http::endpoint
