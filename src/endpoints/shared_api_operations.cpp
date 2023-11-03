#include "shared_api_operations.hpp"

#include "globals.hpp"
#include "log.hpp"
#include "session.hpp"
#include "version.hpp"

#include <irods/atomic_apply_acl_operations.h>
#include <irods/atomic_apply_metadata_operations.h>
#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rodsErrorTable.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <string_view>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace fs  = irods::experimental::filesystem;
namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

namespace irods::http::shared_api_operations
{
	IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE(op_atomic_apply_acl_operations)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _entity_type, _args = std::move(_args)] {
				log::info("{}: client_info.username = [{}]", fn, client_info.username);

				::http::response<::http::string_body> res{::http::status::ok, _req.version()};
				res.set(::http::field::server, irods::http::version::server_name);
				res.set(::http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto lpath_iter = _args.find("lpath");
					if (lpath_iter == std::end(_args)) {
						log::error("{}: Missing [lpath] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, ::http::status::bad_request));
					}

					const auto operations_iter = _args.find("operations");
					if (operations_iter == std::end(_args)) {
						log::error("{}: Missing [operations] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, ::http::status::bad_request));
					}

					auto conn = irods::get_connection(client_info.username);

					// Verify the logical path points to the entity type we expect.
					switch (_entity_type) {
						case entity_type::data_object:
							if (!fs::client::is_data_object(conn, lpath_iter->second)) {
								return _sess_ptr->send(irods::http::fail(
									res,
									::http::status::bad_request,
									json{{"irods_response", {{"status_code", NOT_A_DATA_OBJECT}}}}.dump()));
							}
							break;

						case entity_type::collection:
							if (!fs::client::is_collection(conn, lpath_iter->second)) {
								return _sess_ptr->send(irods::http::fail(
									res,
									::http::status::bad_request,
									json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
							}
							break;

						default:
							return _sess_ptr->send(irods::http::fail(res, ::http::status::bad_request));
					}

					const auto admin_mode_iter = _args.find("admin");

					// clang-format off
					const auto json_input = json{
						{"admin_mode", (admin_mode_iter != std::end(_args) && admin_mode_iter->second == "1")},
						{"logical_path", lpath_iter->second},
						{"operations", json::parse(operations_iter->second)}
					}.dump();
					// clang-format on

					char* output{};
					// NOLINTNEXTLINE(cppcoreguidelines-owning-memory, cppcoreguidelines-no-malloc)
					irods::at_scope_exit_unsafe free_output{[&output] { std::free(output); }};

					const auto ec =
						rc_atomic_apply_acl_operations(static_cast<RcComm*>(conn), json_input.c_str(), &output);

					if (ec != 0) {
						res.result(::http::status::bad_request);
					}

					json response{{"irods_response", {{"status_code", ec}}}};

					if (output) {
						response.at("irods_response")["failed_operation"] = json::parse(output);
					}

					res.body() = response.dump();
				}
				catch (const irods::exception& e) {
					res.result(::http::status::bad_request);
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
					res.result(::http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_atomic_apply_acl_operations

	IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE(op_atomic_apply_metadata_operations)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _entity_type, _args = std::move(_args)] {
				log::info("{}: client_info.username = [{}]", fn, client_info.username);

				::http::response<::http::string_body> res{::http::status::ok, _req.version()};
				res.set(::http::field::server, irods::http::version::server_name);
				res.set(::http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto operations_iter = _args.find("operations");
					if (operations_iter == std::end(_args)) {
						log::error("{}: Missing [operations] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, ::http::status::bad_request));
					}

					std::string_view etype = "http_api_undefined";
					std::string_view ename_param = "http_api_undefined";

					// Verify the logical path points to the entity type we expect.
					switch (_entity_type) {
						case entity_type::data_object:
							etype = "data_object";
							ename_param = "lpath";
							break;

						case entity_type::collection:
							etype = "collection";
							ename_param = "lpath";
							break;

						case entity_type::user:
							etype = "user";
							ename_param = "name";
							break;

						case entity_type::resource:
							etype = "resource";
							ename_param = "name";
							break;

						default:
							log::error("{}: Invalid entity type for atomic metadata operations.", fn);
							return _sess_ptr->send(irods::http::fail(res, ::http::status::bad_request));
					}

					const auto entity_name_iter = _args.find(std::string{ename_param});
					if (entity_name_iter == std::end(_args)) {
						log::error("{}: Missing [{}] parameter.", fn, ename_param);
						return _sess_ptr->send(irods::http::fail(res, ::http::status::bad_request));
					}

					const auto admin_mode_iter = _args.find("admin");

					// clang-format off
					const auto json_input = json{
						{"admin_mode", (admin_mode_iter != std::end(_args) && admin_mode_iter->second == "1")},
						{"entity_name", entity_name_iter->second},
						{"entity_type", etype},
						{"operations", json::parse(operations_iter->second)}
					}.dump();
					// clang-format on

					char* output{};
					// NOLINTNEXTLINE(cppcoreguidelines-owning-memory, cppcoreguidelines-no-malloc)
					irods::at_scope_exit_unsafe free_output{[&output] { std::free(output); }};

					auto conn = irods::get_connection(client_info.username);
					const auto ec =
						rc_atomic_apply_metadata_operations(static_cast<RcComm*>(conn), json_input.c_str(), &output);

					if (ec != 0) {
						res.result(::http::status::bad_request);
					}

					json response{{"irods_response", {{"status_code", ec}}}};

					if (output) {
						response.at("irods_response")["failed_operation"] = json::parse(output);
					}

					res.body() = response.dump();
				}
				catch (const irods::exception& e) {
					res.result(::http::status::bad_request);
					// clang-format off
					res.body() = json{
						{"irods_response", {
							{"status_code", e.code()},
							{"status_message", e.client_display_what()}}
						}
					}.dump();
					// clang-format on
				}
				catch (const std::exception& e) {
					res.result(::http::status::internal_server_error);
				}

				res.prepare_payload();

				return _sess_ptr->send(std::move(res));
			});
	} // op_atomic_apply_metadata_operations
} // namespace irods::http::shared_api_operations
