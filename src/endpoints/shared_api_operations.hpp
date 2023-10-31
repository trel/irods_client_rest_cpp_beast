#ifndef IRODS_HTTP_API_SHARED_API_OPERATIONS_HPP
#define IRODS_HTTP_API_SHARED_API_OPERATIONS_HPP

#include "common.hpp"

#ifndef IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE
// Enables all shared api function signatures for declarations and definitions to be
// updated from one location.
#  define IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE(name) \
	auto name(                                                         \
		irods::http::session_pointer_type _sess_ptr,                   \
		irods::http::request_type& _req,                               \
		irods::http::query_arguments_type& _args,                      \
		const entity_type _entity_type)                                \
		->void
#endif // IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE

namespace irods::http::shared_api_operations
{
	enum class entity_type
	{
		data_object,
		collection,
		user,
		resource
	}; // enum class entity_type

	IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE(op_atomic_apply_acl_operations);

	IRODS_HTTP_API_SHARED_API_OPERATION_FUNCTION_SIGNATURE(op_atomic_apply_metadata_operations);
} // namespace irods::http::shared_api_operations

#endif // IRODS_HTTP_API_SHARED_API_OPERATIONS_HPP
