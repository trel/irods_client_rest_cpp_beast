#include "handlers.hpp"

#include "common.hpp"
#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcMisc.h>
#include <irods/zone_report.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <string>

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(zones)
	{
		namespace log = irods::http::log;

		if (_req.method() != boost::beast::http::verb::get) {
			log::error("{}: Incorrect HTTP method.", __func__);
			return _sess_ptr->send(fail(status_type::method_not_allowed));
		}

		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task([fn = __func__, client_info, _sess_ptr, _req = std::move(_req)] {
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			const auto url = irods::http::parse_url(_req);

			const auto op_iter = url.query.find("op");
			if (op_iter == std::end(url.query)) {
				log::error("{}: Missing [op] parameter.", fn);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (op_iter->second != "report") {
				log::error("{}: Invalid [op] value.", fn);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			BytesBuf* bbuf{};
			irods::at_scope_exit free_bbuf{[&bbuf] { freeBBuf(bbuf); }};

			{
				auto conn = irods::get_connection(client_info.username);

				if (const auto ec = rcZoneReport(static_cast<RcComm*>(conn), &bbuf); ec != 0) {
					log::error("{}: rcZoneReport error: [{}]", fn, ec);
					return _sess_ptr->send(irods::http::fail(status_type::bad_request));
				}
			}

			response_type res{status_type::ok, _req.version()};
			res.set(field_type::server, irods::http::version::server_name);
			res.set(field_type::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				res.body() = fmt::format(
					R"_irods_({{"irods_response":{{"status_code":0}},"zone_report":{}}})_irods_",
					std::string_view(static_cast<char*>(bbuf->buf), bbuf->len));
			}
			catch (const std::exception& e) {
				log::error("{}: Caught exception while writing zone report to HTTP body: {}", fn, e.what());
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // zones
} //namespace irods::http::handler
