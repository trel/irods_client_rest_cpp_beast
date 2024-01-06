#include "irods/private/http_api/handlers.hpp"

#include "irods/private/http_api/common.hpp"
#include "irods/private/http_api/globals.hpp"
#include "irods/private/http_api/log.hpp"
#include "irods/private/http_api/session.hpp"
#include "irods/private/http_api/shared_api_operations.hpp"
#include "irods/private/http_api/version.hpp"

#include <irods/collCreate.h>
#include <irods/dataObjInpOut.h>
#include <irods/filesystem.hpp>
#include <irods/filesystem/path_utilities.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcMisc.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/system_error.hpp> // For make_error_code
#include <irods/touch.h>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

namespace fs  = irods::experimental::filesystem;
namespace log = irods::http::log;

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
	using handler_type =
		void (*)(irods::http::session_pointer_type, irods::http::request_type&, irods::http::query_arguments_type&);

	//
	// Handler function prototypes
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_stat);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_create);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_rename);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_set_permission);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_modify_permissions);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_modify_metadata);
	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_touch);

	//
	// Operation to Handler mappings
	//

	// clang-format off
	const std::unordered_map<std::string, handler_type> handlers_for_get{
		{"list", op_list},
		{"stat", op_stat}
	};

	const std::unordered_map<std::string, handler_type> handlers_for_post{
		{"create", op_create},
		{"remove", op_remove},
		{"rename", op_rename},
		//{"copy", op_copy}, // TODO
		{"set_permission", op_set_permission},
		//{"enable_inheritance", op_enable_inheritance} // TODO set_permission handles inheritance?
		{"modify_permissions", op_modify_permissions},
		{"modify_metadata", op_modify_metadata},
		{"touch", op_touch}
	};
	// clang-format on
} // anonymous namespace

namespace irods::http::handler
{
	// NOLINTNEXTLINE(performance-unnecessary-value-param)
	IRODS_HTTP_API_ENDPOINT_ENTRY_FUNCTION_SIGNATURE(collections)
	{
		if (_req.method() == verb_type::get) {
			auto url = irods::http::parse_url(_req);

			const auto op_iter = url.query.find("op");
			if (op_iter == std::end(url.query)) {
				log::error("{}: Missing [op] parameter.", __func__);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
				return (iter->second)(_sess_ptr, _req, url.query);
			}

			return _sess_ptr->send(fail(status_type::bad_request));
		}

		if (_req.method() == verb_type::post) {
			auto args = irods::http::to_argument_list(_req.body());

			const auto op_iter = args.find("op");
			if (op_iter == std::end(args)) {
				log::error("{}: Missing [op] parameter.", __func__);
				return _sess_ptr->send(irods::http::fail(status_type::bad_request));
			}

			if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
				return (iter->second)(_sess_ptr, _req, args);
			}

			return _sess_ptr->send(fail(status_type::bad_request));
		}

		log::error("{}: Incorrect HTTP method.", __func__);
		return _sess_ptr->send(irods::http::fail(status_type::method_not_allowed));
	} // collections
} // namespace irods::http::handler

namespace
{
	//
	// Operation handler implementations
	//

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_list)
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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					log::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto conn = irods::get_connection(client_info.username);

				// Enable ticket if the request includes one.
				if (const auto iter = _args.find("ticket"); iter != std::end(_args)) {
					if (const auto ec = irods::enable_ticket(conn, iter->second); ec < 0) {
						res.result(http::status::internal_server_error);
						res.body() =
							json{{"irods_response",
						          {{"status_code", ec}, {"status_message", "Error enabling ticket on connection."}}}}
								.dump();
						res.prepare_payload();
						return _sess_ptr->send(std::move(res));
					}
				}

				if (!fs::client::is_collection(conn, lpath_iter->second)) {
					return _sess_ptr->send(irods::http::fail(
						res,
						http::status::bad_request,
						json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
				}

				json entries;

				const auto recursive_iter = _args.find("recurse");
				if (recursive_iter != std::end(_args) && recursive_iter->second == "1") {
					for (auto&& e : fs::client::recursive_collection_iterator{conn, lpath_iter->second}) {
						entries.push_back(e.path().c_str());
					}
				}
				else {
					for (auto&& e : fs::client::collection_iterator{conn, lpath_iter->second}) {
						entries.push_back(e.path().c_str());
					}
				}

				res.body() = json{{"irods_response", {{"status_code", 0}}}, {"entries", entries}}.dump();
			}
			catch (const fs::filesystem_error& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}.dump();
			}
			catch (const irods::exception& e) {
				log::error("{}: {}", fn, e.client_display_what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_list

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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					log::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto conn = irods::get_connection(client_info.username);

				// Enable ticket if the request includes one.
				if (const auto iter = _args.find("ticket"); iter != std::end(_args)) {
					if (const auto ec = irods::enable_ticket(conn, iter->second); ec < 0) {
						res.result(http::status::internal_server_error);
						res.body() =
							json{{"irods_response",
						          {{"status_code", ec}, {"status_message", "Error enabling ticket on connection."}}}}
								.dump();
						res.prepare_payload();
						return _sess_ptr->send(std::move(res));
					}
				}

				const auto status = fs::client::status(conn, lpath_iter->second);

				if (!fs::client::is_collection(status)) {
					return _sess_ptr->send(irods::http::fail(
						res,
						http::status::bad_request,
						json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
				}

				json perms;
				for (auto&& ep : status.permissions()) {
					perms.push_back(json{
						{"name", ep.name},
						{"zone", ep.zone},
						{"type", ep.type},
						{"perm", irods::to_permission_string(ep.prms)},
					});
				}

				res.body() =
					json{
						{"irods_response", {{"status_code", 0}}},
						{"type", irods::to_object_type_string(status.type())},
						{"inheritance_enabled", status.is_inheritance_enabled()},
						{"permissions", perms},
						{"registered", fs::client::is_collection_registered(conn, lpath_iter->second)},
						{"modified_at",
				         fs::client::last_write_time(conn, lpath_iter->second).time_since_epoch().count()}}
						.dump();
			}
			catch (const fs::filesystem_error& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}.dump();
			}
			catch (const irods::exception& e) {
				log::error("{}: {}", fn, e.client_display_what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_stat

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_create)
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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					log::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto conn = irods::get_connection(client_info.username);
				bool created = false;
				int ec = 0;
				const auto iter = _args.find("create-intermediates");

				if (iter != std::end(_args) && iter->second == "1") {
					//
					// This branch implements a modified version of irods::filesystem::_::create_collections().
					// These changes may be absorbed into the filesystem library. If that happens, don't forget
					// to update this code block to use the official implementation.
					//

					fs::throw_if_path_length_exceeds_limit(lpath_iter->second);

					if (!fs::client::exists(conn, lpath_iter->second)) {
						CollInp input{};
						irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};

						lpath_iter->second.copy(input.collName, sizeof(CollInp::collName) - 1);
						addKeyVal(&input.condInput, RECURSIVE_OPR__KW, "");

						ec = rcCollCreate(static_cast<RcComm*>(conn), &input);
						if (ec < 0) {
							throw fs::filesystem_error{
								"cannot create collection",
								lpath_iter->second,
								irods::experimental::make_error_code(ec)};
						}

						created = (ec >= 0);
					}
				}
				else {
					created = fs::client::create_collection(conn, lpath_iter->second);
				}

				// clang-format off
				res.body() = json{
					{"irods_response", {
						{"status_code", ec}
					}},
					{"created", created}
				}.dump();
				// clang-format on
			}
			catch (const fs::filesystem_error& e) {
				log::error("{}: {}", fn, e.what());
				// clang-format off
				res.body() = json{
					{"irods_response", {
						{"status_code", e.code().value()},
						{"status_message", e.what()}
					}}
				}.dump();
				// clang-format on
			}
			catch (const irods::exception& e) {
				log::error("{}: {}", fn, e.client_display_what());
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
				log::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_create

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_remove)
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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					log::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto conn = irods::get_connection(client_info.username);

				if (!fs::client::is_collection(conn, lpath_iter->second)) {
					return _sess_ptr->send(irods::http::fail(
						res,
						http::status::bad_request,
						json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
				}

				fs::remove_options opts = fs::remove_options::none;

				const auto no_trash_iter = _args.find("no-trash");
				if (no_trash_iter != std::end(_args) && no_trash_iter->second == "1") {
					opts = fs::remove_options::no_trash;
				}

				const auto recursive_iter = _args.find("recurse");
				if (recursive_iter != std::end(_args) && recursive_iter->second == "1") {
					fs::client::remove_all(conn, lpath_iter->second, opts);
				}
				else {
					fs::client::remove(conn, lpath_iter->second, opts);
				}

				res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
			}
			catch (const fs::filesystem_error& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}.dump();
			}
			catch (const irods::exception& e) {
				log::error("{}: {}", fn, e.client_display_what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_remove

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_rename)
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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto old_lpath_iter = _args.find("old-lpath");
				if (old_lpath_iter == std::end(_args)) {
					log::error("{}: Missing [old-lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto conn = irods::get_connection(client_info.username);

				if (!fs::client::is_collection(conn, old_lpath_iter->second)) {
					return _sess_ptr->send(irods::http::fail(
						res,
						http::status::bad_request,
						json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
				}

				const auto new_lpath_iter = _args.find("new-lpath");
				if (new_lpath_iter == std::end(_args)) {
					log::error("{}: Missing [new-lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				try {
					fs::client::rename(conn, old_lpath_iter->second, new_lpath_iter->second);

					res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
				}
				catch (const fs::filesystem_error& e) {
					log::error("{}: {}", fn, e.what());
					res.result(http::status::bad_request);
					res.body() =
						json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}
							.dump();
				}
			}
			catch (const fs::filesystem_error& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}.dump();
			}
			catch (const irods::exception& e) {
				log::error("{}: {}", fn, e.client_display_what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_rename

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_set_permission)
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
			log::info("{}: client_info.username = [{}]", fn, client_info.username);

			http::response<http::string_body> res{http::status::ok, _req.version()};
			res.set(http::field::server, irods::http::version::server_name);
			res.set(http::field::content_type, "application/json");
			res.keep_alive(_req.keep_alive());

			try {
				const auto lpath_iter = _args.find("lpath");
				if (lpath_iter == std::end(_args)) {
					log::error("{}: Missing [lpath] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				auto conn = irods::get_connection(client_info.username);

				if (!fs::client::is_collection(conn, lpath_iter->second)) {
					return _sess_ptr->send(irods::http::fail(
						res,
						http::status::bad_request,
						json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
				}

				const auto entity_name_iter = _args.find("entity-name");
				if (entity_name_iter == std::end(_args)) {
					log::error("{}: Missing [entity-name] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				const auto perm_iter = _args.find("permission");
				if (perm_iter == std::end(_args)) {
					log::error("{}: Missing [permission] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				const auto perm_enum = irods::to_permission_enum(perm_iter->second);
				if (!perm_enum) {
					log::error("{}: Invalid value for [permission] parameter.", fn);
					return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
				}

				try {
					const auto admin_mode_iter = _args.find("admin");
					if (admin_mode_iter != std::end(_args) && admin_mode_iter->second == "1") {
						fs::client::permissions(
							fs::admin, conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
					}
					else {
						fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
					}

					res.body() = json{{"irods_response", {{"status_code", 0}}}}.dump();
				}
				catch (const fs::filesystem_error& e) {
					log::error("{}: {}", fn, e.what());
					res.body() =
						json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}
							.dump();
				}
			}
			catch (const fs::filesystem_error& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code().value()}, {"status_message", e.what()}}}}.dump();
			}
			catch (const irods::exception& e) {
				log::error("{}: {}", fn, e.client_display_what());
				res.result(http::status::bad_request);
				res.body() =
					json{{"irods_response", {{"status_code", e.code()}, {"status_message", e.client_display_what()}}}}
						.dump();
			}
			catch (const std::exception& e) {
				log::error("{}: {}", fn, e.what());
				res.result(http::status::internal_server_error);
			}

			res.prepare_payload();

			return _sess_ptr->send(std::move(res));
		});
	} // op_set_permission

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_modify_permissions)
	{
		using namespace irods::http::shared_api_operations;
		return op_atomic_apply_acl_operations(_sess_ptr, _req, _args, entity_type::collection);
	} // op_modify_permissions

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_modify_metadata)
	{
		using namespace irods::http::shared_api_operations;
		return op_atomic_apply_metadata_operations(_sess_ptr, _req, _args, entity_type::collection);
	} // op_modify_metadata

	IRODS_HTTP_API_ENDPOINT_OPERATION_SIGNATURE(op_touch)
	{
		auto result = irods::http::resolve_client_identity(_req);
		if (result.response) {
			return _sess_ptr->send(std::move(*result.response));
		}

		const auto client_info = result.client_info;

		irods::http::globals::background_task(
			[fn = __func__, client_info, _sess_ptr, _req = std::move(_req), _args = std::move(_args)] {
				log::info("{}: client_info.username = [{}]", fn, client_info.username);

				http::response<http::string_body> res{http::status::ok, _req.version()};
				res.set(http::field::server, irods::http::version::server_name);
				res.set(http::field::content_type, "application/json");
				res.keep_alive(_req.keep_alive());

				try {
					const auto lpath_iter = _args.find("lpath");
					if (lpath_iter == std::end(_args)) {
						log::error("{}: Missing [lpath] parameter.", fn);
						return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
					}

					// DO NOT allow data objects to be created.
					json::object_t options{{"no_create", true}};

					auto opt_iter = _args.find("seconds-since-epoch");
					if (opt_iter != std::end(_args)) {
						try {
							options["seconds_since_epoch"] = std::stoi(opt_iter->second);
						}
						catch (const std::exception& e) {
							log::error(
								"{}: Could not convert seconds-since-epoch [{}] into an integer.",
								fn,
								opt_iter->second);
							return _sess_ptr->send(irods::http::fail(res, http::status::bad_request));
						}
					}

					opt_iter = _args.find("reference");
					if (opt_iter != std::end(_args)) {
						options["reference"] = opt_iter->second;
					}

					const json input{{"logical_path", lpath_iter->second}, {"options", options}};

					auto conn = irods::get_connection(client_info.username);

					const auto status = fs::client::status(conn, lpath_iter->second);

					if (fs::client::exists(status) && !fs::client::is_collection(status)) {
						return _sess_ptr->send(irods::http::fail(
							res,
							http::status::bad_request,
							json{{"irods_response", {{"status_code", NOT_A_COLLECTION}}}}.dump()));
					}

					const auto ec = rc_touch(static_cast<RcComm*>(conn), input.dump().c_str());

					res.body() = json{{"irods_response", {{"status_code", ec}}}}.dump();
				}
				catch (const irods::exception& e) {
					log::error("{}: {}", fn, e.client_display_what());
					res.result(http::status::bad_request);
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
					log::error("{}: {}", fn, e.what());
					res.result(http::status::internal_server_error);
				}

				res.prepare_payload();

				_sess_ptr->send(std::move(res));
			});
	} // op_touch
} // anonymous namespace
