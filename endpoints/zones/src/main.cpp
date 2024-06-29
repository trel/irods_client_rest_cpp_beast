#include "irods/private/http_api/handlers.hpp"

#include "irods/private/http_api/common.hpp"
#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/session.hpp"
#include "irods/private/http_api/version.hpp"

#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcMisc.h>
#include <irods/zone_administration.hpp>
#include <irods/zone_report.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <string>
#include <string_view>
#include <unordered_map>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>

namespace adm     = irods::experimental::administration;
namespace logging = irods::http::log;

using json = nlohmann::json;
// clang-format on

#define IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(name) \
  auto name(                                              \
	  irods::http::session_pointer_type _sess_ptr,        \
	  irods::http::request_type& _req,                    \
	  irods::http::query_arguments_type& _args)           \
	  ->void

namespace
{
	//
	// Handler function prototypes
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_report);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_stat);

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_add);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_modify);
	// TODO(#290): Enable once "iadmin modzonecollacl" is fully understood.
	//IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_set_zone_collection_permission);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, irods::http::handler_type> handlers_for_get{
		{"report", op_report},
		{"stat", op_stat}
	};

	const std::unordered_map<std::string, irods::http::handler_type> handlers_for_post{
		{"add", op_add},
		{"remove", op_remove},
		{"modify", op_modify},
		// TODO(#290): Enable once "iadmin modzonecollacl" is fully understood.
		//{"set_zone_collection_permission", op_set_zone_collection_permission}
	};
	// clang-format on
} // anonymous namespace

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(zones)
	{
		execute_operation(_sess_ptr, _req, handlers_for_get, handlers_for_post);
	} // zones
} // namespace irods::http::handler

namespace
{
	//
	// Operation handler implementations
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_add)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto name_iter = _args.find("name");
					if (name_iter == std::end(_args)) {
						logging::error("{}: Missing [name] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					adm::zone_options opts;

					auto connection_info_iter = _args.find("connection-info");
					if (connection_info_iter != std::end(_args)) {
						opts.connection_info = std::move(connection_info_iter->second);
					}

					auto comment_iter = _args.find("comment");
					if (comment_iter != std::end(_args)) {
						opts.comment = std::move(comment_iter->second);
					}

					auto conn = irods::get_connection(client_info.username);
					adm::client::add_zone(conn, name_iter->second, opts);

					res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
				}
				catch (const irods::exception& e) {
					logging::error("{}: {}", fn, e.client_display_what());
					// clang-format off
					res.body() = json{
						{"irods_response", {
							{"status_code", e.code()},
							{"status_message", e.client_display_what()}
						}}
					}.dump();
					// clang-format on
				}
				catch (const std::exception& e) {
					logging::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_add

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto name_iter = _args.find("name");
					if (name_iter == std::end(_args)) {
						logging::error("{}: Missing [name] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					auto conn = irods::get_connection(client_info.username);
					adm::client::remove_zone(conn, name_iter->second);

					res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
				}
				catch (const irods::exception& e) {
					logging::error("{}: {}", fn, e.client_display_what());
					// clang-format off
					res.body() = json{
						{"irods_response", {
							{"status_code", e.code()},
							{"status_message", e.client_display_what()}
						}}
					}.dump();
					// clang-format on
				}
				catch (const std::exception& e) {
					logging::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_remove

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_modify)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto name_iter = _args.find("name");
					if (name_iter == std::end(_args)) {
						logging::error("{}: Missing [name] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					const auto property_iter = _args.find("property");
					if (property_iter == std::end(_args)) {
						logging::error("{}: Missing [property] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					const auto value_iter = _args.find("value");
					if (value_iter == std::end(_args)) {
						logging::error("{}: Missing [value] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					auto conn = irods::get_connection(client_info.username);

					if (property_iter->second == "name") {
						adm::client::modify_zone(conn, name_iter->second, adm::zone_name_property{value_iter->second});
					}
					else if (property_iter->second == "connection_info") {
						adm::client::modify_zone(
							conn, name_iter->second, adm::connection_info_property{value_iter->second});
					}
					else if (property_iter->second == "comment") {
						adm::client::modify_zone(conn, name_iter->second, adm::comment_property{value_iter->second});
					}
					else {
						logging::error("{}: Invalid value for [property] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
				}
				catch (const irods::exception& e) {
					logging::error("{}: {}", fn, e.client_display_what());
					// clang-format off
					res.body() = json{
						{"irods_response", {
							{"status_code", e.code()},
							{"status_message", e.client_display_what()}
						}}
					}.dump();
					// clang-format on
				}
				catch (const std::exception& e) {
					logging::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_modify

	// TODO(#290): Enable once "iadmin modzonecollacl" is fully understood.
#if 0
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_set_zone_collection_permission)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto name_iter = _args.find("name");
					if (name_iter == std::end(_args)) {
						logging::error("{}: Missing [name] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					const auto perm_iter = _args.find("permission");
					if (perm_iter == std::end(_args)) {
						logging::error("{}: Missing [permission] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					// TODO(#291) Investigate whether fully-qualified usernames are supported.
					const auto user_iter = _args.find("user");
					if (user_iter == std::end(_args)) {
						logging::error("{}: Missing [user] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					auto acl = adm::zone_collection_acl::null;
					if (perm_iter->second == "read") {
						acl = adm::zone_collection_acl::read;
					}
					else if (perm_iter->second != "null") {
						logging::error(
							"{}: Invalid value for [permission] parameter. Received [{}]. Expected [null] or [read].",
							fn,
							perm_iter->second);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					auto conn = irods::get_connection(client_info.username);

					adm::client::modify_zone(
						conn, name_iter->second, adm::zone_collection_acl_property{acl, user_iter->second});

					res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
				}
				catch (const irods::exception& e) {
					logging::error("{}: {}", fn, e.client_display_what());
					// clang-format off
					res.body() = json{
						{"irods_response", {
							{"status_code", e.code()},
							{"status_message", e.client_display_what()}
						}}
					}.dump();
					// clang-format on
				}
				catch (const std::exception& e) {
					logging::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_set_zone_collection_permission
#endif

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_report)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				logging::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					BytesBuf* bbuf{};
					irods::at_scope_exit free_bbuf{[&bbuf] { freeBBuf(bbuf); }};

					{
						auto conn = irods::get_connection(client_info.username);

						if (const auto ec = rcZoneReport(static_cast<RcComm*>(conn), &bbuf); ec != 0) {
							logging::error("{}: rcZoneReport error: [{}]", fn, ec);
							// clang-format off
							res.body() = json{
								{"irods_response", {
									{"status_code", ec},
									{"status_message", "Could not generate zone report."}
								}}
							}.dump();
							// clang-format on
							res.prepare_payload();
							return _sess_ptr->send(std::move(res));
						}
					}

					res.body() = fmt::format(
						R"_irods_({{"irods_response":{{"status_code":0}},"zone_report":{}}})_irods_",
						std::string_view(static_cast<char*>(bbuf->buf), bbuf->len));
				}
				catch (const irods::exception& e) {
					logging::error("{}: {}", fn, e.client_display_what());
					// clang-format off
					res.body() = json{
						{"irods_response", {
							{"status_code", e.code()},
							{"status_message", e.client_display_what()}
						}}
					}.dump();
					// clang-format on
				}
				catch (const std::exception& e) {
					logging::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_report

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_stat)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task([fn = __func__,
		                                       client_info,
		                                       _sess_ptr,
		                                       _req = std::move(_req),
		                                       _args = std::move(_args)] {
			logging::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto name_iter = _args.find("name");
				if (name_iter == std::end(_args)) {
					logging::error("{}: Missing [name] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				std::optional<adm::zone_info> zone;

				{
					auto conn = irods::get_connection(client_info.username);
					zone = adm::client::zone_info(conn, name_iter->second);
				}

				json::object_t info;
				auto exists = false;

				if (zone) {
					exists = true;

					// clang-format off
					info = {
						{"id", zone->id},
						{"name", zone->name},
						{"connection_info", zone->connection_info},
						{"comment", zone->comment},
						{"type", (zone->type == adm::zone_type::local) ? "local" : "remote"}
					};
					// clang-format on
				}

				// clang-format off
				res.body() = json{
					{"irods_response", {{"status_code", 0}}},
					{"exists", exists},
					{"info", info}
				}.dump();
				// clang-format on
			}
			catch (const irods::exception& e) {
				logging::error("{}: {}", fn, e.client_display_what());
				// clang-format off
				res.body() = json{
					{"irods_response", {
						{"status_code", e.code()},
						{"status_message", e.client_display_what()}
					}}
				}.dump();
				// clang-format on
			}
			catch (const std::exception& e) {
				logging::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_stat
} //namespace
