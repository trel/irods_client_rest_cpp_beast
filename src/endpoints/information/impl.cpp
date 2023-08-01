#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/irods_exception.hpp>

#include <boost/beast.hpp>
#include <nlohmann/json.hpp>

#include <string>

namespace irods::http::handler
{
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(information)
    {
        if (_req.method() != boost::beast::http::verb::get) {
            return _sess_ptr->send(fail(status_type::method_not_allowed));
        }

        const auto& svr = irods::http::globals::configuration().at("irods_client");

        using json = nlohmann::json;

        response_type res{status_type::ok, _req.version()};
        res.set(field_type::server, irods::http::version::server_name);
        res.set(field_type::content_type, "application/json");
        res.keep_alive(_req.keep_alive());

#ifdef IRODS_ENABLE_GENQUERY2
#  define GENQUERY2_ENABLED true
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#  define GENQUERY2_ENABLED false
#endif // IRODS_ENABLE_GENQUERY2

        res.body() = json{
            {"api_version", irods::http::version::api_version},
            {"build", irods::http::version::sha},
            {"irods_zone", svr.at("zone")},
            {"genquery2_enabled", GENQUERY2_ENABLED},
        }.dump();

        res.prepare_payload();

        return _sess_ptr->send(std::move(res));
    } // information
} // namespace irods::http::endpoint
