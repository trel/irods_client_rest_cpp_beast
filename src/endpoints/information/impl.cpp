#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/client_connection.hpp>
#include <irods/irods_exception.hpp>

#include <boost/beast.hpp>
#include <nlohmann/json.hpp>

#include <string>

namespace irods::http::handler
{
    auto information(session_pointer_type _sess_ptr, request_type& _req) -> void
    {
        if (_req.method() != boost::beast::http::verb::get) {
            return _sess_ptr->send(fail(status_type::method_not_allowed));
        }

        const auto& svr = irods::http::globals::config->at("irods_client");

        using json = nlohmann::json;

        response_type res{status_type::ok, _req.version()};
        res.set(field_type::server, BOOST_BEAST_VERSION_STRING);
        res.set(field_type::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

        res.body() = json{
            //{"binary_name", irods::http::version::binary_name}, // TODO Remove?
            {"api_version", irods::http::version::api_version},
            {"build", irods::http::version::sha},
#if 0
            {"irods_server", {
                {"host", svr.at("host")},
                {"port", svr.at("port")},
                {"zone", svr.at("zone")}
            }}
#else
            {"irods_zone", svr.at("zone")}
#endif
        }.dump();

        res.prepare_payload();

        return _sess_ptr->send(std::move(res));
    } // information
} // namespace irods::http::endpoint
