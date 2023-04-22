#include "handlers.hpp"

#include "common.hpp"
#include "log.hpp"

#include <irods/client_connection.hpp>
#include <irods/dataObjRepl.h>
#include <irods/dataObjTrim.h>
#include <irods/filesystem.hpp>
#include <irods/irods_exception.hpp>
#include <irods/rcMisc.h>
#include <irods/rodsErrorTable.h>
#include <irods/touch.h>

#include <irods/transport/default_transport.hpp>
#include <irods/dstream.hpp>

#include <boost/asio.hpp>
//#include <boost/asio/ip/tcp.hpp> // TODO Remove
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>

#include <nlohmann/json.hpp>

#include <span>
#include <string>
//#include <string_view>
#include <unordered_map>
#include <vector>

// clang-format off
namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http  = beast::http;      // from <boost/beast/http.hpp>
namespace net   = boost::asio;      // from <boost/asio.hpp>

//using tcp = boost::asio::ip::tcp;   // from <boost/asio/ip/tcp.hpp> // TODO Remove

namespace fs  = irods::experimental::filesystem;
namespace io  = irods::experimental::io;
namespace log = irods::http::log;

using json = nlohmann::json;
// clang-format on

namespace
{
    // clang-format off
    using query_arguments_type = decltype(irods::http::url::query);
    using handler_type         = irods::http::response_type(*)(const irods::http::request_type& _req, const query_arguments_type& _args);
    // clang-format on

    struct parallel_write_stream
    {
        irods::experimental::client_connection conn{irods::experimental::defer_connection};
        std::unique_ptr<irods::experimental::io::client::native_transport> tp;
        irods::experimental::io::odstream out;
    }; // struct parallel_write_stream

    struct parallel_write_context
    {
        std::string logical_path;
        std::vector<std::shared_ptr<parallel_write_stream>> streams;
    }; // struct parallel_write_context

    std::unordered_map<std::string, parallel_write_context> parallel_write_contexts;

    //
    // Handler function prototypes
    //

    auto handle_read_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_write_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_parallel_write_init_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_parallel_write_shutdown_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    auto handle_replicate_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_trim_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    auto handle_set_permission_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    auto handle_register_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_unregister_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    auto handle_rename_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_remove_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;
    auto handle_touch_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type;

    //
    // Operation to Handler mappings
    //

    const std::unordered_map<std::string, handler_type> handlers_for_get{
        {"read", handle_read_op},
        {"stat", handle_stat_op}
    };

    const std::unordered_map<std::string, handler_type> handlers_for_post{
        {"touch", handle_touch_op},
        {"remove", handle_remove_op},

        {"write", handle_write_op},
        {"parallel_write_init", handle_parallel_write_init_op},
        {"parallel_write_shutdown", handle_parallel_write_shutdown_op},

        {"rename", handle_rename_op},
        //{"copy", handle_copy_op},

        {"replicate", handle_replicate_op},
        {"trim", handle_trim_op},

        {"register", handle_register_op},
        {"unregister", handle_unregister_op},

        {"set_permission", handle_set_permission_op}

        //{"calculate_checksum", handle_calculate_checksum},
        //{"register_checksum", handle_register_checksum},
        //{"verify_checksum", handle_verify_checksum},

        //{"physical_move", handle_physical_move},
    };
} // anonymous namespace

namespace irods::http::handler
{
    // Handles all requests sent to /data_objects.
    auto data_objects(const request_type& _req) -> response_type
    {
        if (_req.method() == verb_type::get) {
            const auto url = irods::http::parse_url(_req);

            const auto op_iter = url.query.find("op");
            if (op_iter == std::end(url.query)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return irods::http::fail(status_type::bad_request);
            }

            if (const auto iter = handlers_for_get.find(op_iter->second); iter != std::end(handlers_for_get)) {
                return (iter->second)(_req, url.query);
            }
        }
        else if (_req.method() == verb_type::post) {
            const auto args = irods::http::to_argument_list(_req.body());

            const auto op_iter = args.find("op");
            if (op_iter == std::end(args)) {
                log::error("{}: Missing [op] parameter.", __func__);
                return irods::http::fail(status_type::bad_request);
            }

            if (const auto iter = handlers_for_post.find(op_iter->second); iter != std::end(handlers_for_post)) {
                return (iter->second)(_req, args);
            }
        }

        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(status_type::method_not_allowed);
    } // data_objects
} // namespace irods::http::handler

namespace
{
    //
    // Operation handler implementations
    //

    auto handle_read_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            // TODO Inputs:
            // - offset
            // - count
            //     - content-length vs query parameter
            //     - How about chunked encoding?
            //
            // TODO Should a client care about a specific replica when reading?
            // TODO Should a client be allowed to target a leaf resource?

            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            // TODO While dstream makes reading/writing simple, using it means we lose the
            // ability to know why an operation failed. This is because dstream or the transport
            // doesn't expose the internal details for a failure. And IOStreams don't throw exceptions
            // unless they are configured to do so, which leads to very ugly/weird code.
            //
            // With that said, this operation can only report what it thinks may have happened. The
            // client will have to contact the iRODS administrator to have them check the logs.
            //
            // Alternatively, we can make C API calls and get the exact reasons for a failure. This is
            // more work, but will allow the client to make better decisions about what to do next.

            irods::experimental::client_connection conn;
            io::client::native_transport tp{conn};
            io::idstream in{tp, lpath_iter->second};

            if (!in) {
                log::error("{}: Could not open data object [{}] for read.", __func__, lpath_iter->second);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                    }},
                    // TODO REST API internal error. Do we need REST API error codes to
                    // indicate the issue was not iRODS related (we never reached out to iRODS)?
                    {"http_api_error_code", -1}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                    {"http_api_error_message", "Open error."}
                }.dump();
                res.prepare_payload();

                return res;
            }

            // TODO This needs to be clamped to a max size set by the administrator.
            // Should this be required?
            auto iter = _args.find("offset");
            if (iter != std::end(_args)) {
                try {
                    in.seekg(std::stoll(iter->second));
                }
                catch (const std::exception& e) {
                    log::error("{}: Could not seek to position [{}] in data object [{}].", __func__, iter->second, lpath_iter->second);

                    res.body() = json{
                        {"irods_response", {
                            {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                        }},
                        // TODO REST API internal error. Do we need REST API error codes to
                        // indicate the issue was not iRODS related (we never reached out to iRODS)?
                        {"http_api_error_code", -2}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                        {"http_api_error_message", "Seek error."}
                    }.dump();
                    res.prepare_payload();

                    return res;
                }
            }

            std::vector<char> buffer;

            // TODO This needs to be clamped to a max size set by the administrator.
            // Should this be required?
            iter = _args.find("count");
            if (iter != std::end(_args)) {
                try {
                    buffer.resize(std::stoi(iter->second));
                }
                catch (const std::exception& e) {
                    log::error("{}: Could not initialize read buffer to size [{}] for data object [{}].", __func__, iter->second, lpath_iter->second);

                    res.body() = json{
                        {"irods_response", {
                            {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                        }},
                        // TODO REST API internal error. Do we need REST API error codes to
                        // indicate the issue was not iRODS related (we never reached out to iRODS)?
                        {"http_api_error_code", -3}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                        {"http_api_error_message", "Buffer error."}
                    }.dump();
                    res.prepare_payload();

                    return res;
                }
            }
            else {
                buffer.resize(8192);
            }

            // TODO Given a specific number of bytes to read, we can define a loop that reads the
            // requested number of bytes using a fixed size buffer. Obviously, this means multiple
            // read operations are required, but that isn't a problem. The big win for doing this is
            // that we protect the application from exhausting all memory because a client decided
            // to execute multiple reads with a count of N GB buffers.
            //
            // Something else to think about is moving stream operation API calls to a separate
            // thread pool. If there are 10000 clients all performing reads and writes, and all these
            // operations happen within the same threads that are servicing HTTP requests, it is
            // easy to see how new HTTP requests can be blocked due to existing IO operations being
            // serviced.
            //
            // ---
            //
            // Keeping this as is isn't so bad if we can keep the number of read operations to one.
            // The issue with the comment above the separator is we have to store the data in memory
            // or use the chunked encoding. Boost.Beast does support chunked encoding and provides
            // examples showing how to do it.
            in.read(buffer.data(), buffer.size());

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }},
                {"bytes_read", in.gcount()},
                // data will be returned as a buffer of bytes (i.e. integers). The nlohmann JSON
                // library will not view the range as a string. This is what we want.
                {"bytes", std::span(buffer.data(), in.gcount())}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_read_op

    auto handle_write_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            log::trace("{}: Opening data object [{}] for write.", __func__, lpath_iter->second);

            std::unique_ptr<irods::experimental::client_connection> conn;
            std::unique_ptr<io::client::native_transport> tp;

            std::unique_ptr<io::odstream> out;
            io::odstream* out_ptr{};

            const auto parallel_write_handle_iter = _args.find("parallel-write-handle"); 
            if (parallel_write_handle_iter != std::end(_args)) {
                log::debug("{}: (write) Parallel Write Handle = [{}].", __func__, parallel_write_handle_iter->second);

                auto iter = parallel_write_contexts.find(parallel_write_handle_iter->second);
                if (iter == std::end(parallel_write_contexts)) {
                    log::error("{}: Invalid handle for parallel write.", __func__);
                    return irods::http::fail(res, http::status::ok);
                }

                //
                // We've found a matching handle!
                //

                // TODO How do we pick a stream?
                //
                // Should the client have to worry about this? It's easy to let them target a specific stream.
                // It's also more deterministic.
                //
                // TODO This counter needs to be part of the parallel_write_stream.
                static int idx = 0;
                log::debug("{}: (write) Parallel Write - stream index = [{}].", __func__, idx);
                out_ptr = &iter->second.streams[idx]->out;
                ++idx;
                idx %= iter->second.streams.size();
            }
            else {
                log::trace("{}: (write) Initializing for single buffer write.", __func__);
                conn = std::make_unique<irods::experimental::client_connection>();
                tp = std::make_unique<io::client::native_transport>(*conn);
                out = std::make_unique<io::odstream>(*tp, lpath_iter->second);
                out_ptr = out.get();
            }

            if (!*out_ptr) {
                log::error("{}: Could not open data object [{}] for write.", __func__, lpath_iter->second);

                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                    }},
                    // TODO REST API internal error. Do we need REST API error codes to
                    // indicate the issue was not iRODS related (we never reached out to iRODS)?
                    {"http_api_error_code", -1}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                    {"http_api_error_message", "Open error."}
                }.dump();
                res.prepare_payload();

                return res;
            }

            // TODO This needs to be clamped to a max size set by the administrator.
            // Should this be required?
            auto iter = _args.find("offset");
            if (iter != std::end(_args)) {
                log::trace("{}: Setting offset for write.", __func__);
                try {
                    out_ptr->seekp(std::stoll(iter->second));
                }
                catch (const std::exception& e) {
                    log::error("{}: Could not seek to position [{}] in data object [{}].", __func__, iter->second, lpath_iter->second);

                    res.body() = json{
                        {"irods_response", {
                            {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                        }},
                        // TODO REST API internal error. Do we need REST API error codes to
                        // indicate the issue was not iRODS related (we never reached out to iRODS)?
                        {"http_api_error_code", -2}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                        {"http_api_error_message", "Seek error."}
                    }.dump();
                    res.prepare_payload();

                    return res;
                }
            }

            // TODO This needs to be clamped to a max size set by the administrator.
            // Should this be required?
            //
            // The Content-Type header cannot be used for this because it is used to describe the size
            // of the request body. ALL parameters are passed via the request body when using POST.
            iter = _args.find("count");
            if (iter == std::end(_args)) {
                log::error("{}: Missing [count] parameter.", __func__);
                res.result(http::status::bad_request);
                res.prepare_payload();
                return res;
            }
            const auto count = std::stoll(std::string{iter->second});

            iter = _args.find("bytes");
            if (iter == std::end(_args)) {
                log::error("{}: Missing [bytes] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            out_ptr->write(iter->second.data(), count);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_read_op

    auto handle_parallel_write_init_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            // TODO
            // 1. Create a parallel transfer context (PTC).
            // 2. Open one iRODS connection per stream and store in the PTC.
            // 3. Generate a transfer handle and associate it with the Bearer/Access token and PTC.
            // 4. Return transfer handle to client.
            //
            // The client is now free to call the write operation as much as they want.

            const auto stream_count_iter = _args.find("stream-count");
            if (stream_count_iter == std::end(_args)) {
                log::error("{}: Missing [stream-count] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            namespace io = irods::experimental::io;

            log::trace("{}: Opening initial output stream to [{}].", __func__, lpath_iter->second);

            // Open the first stream.
            irods::experimental::client_connection conn;
            auto tp = std::make_unique<io::client::native_transport>(conn);
            io::odstream out{*tp, lpath_iter->second};

            log::trace("{}: Checking if output stream is open for [{}].", __func__, lpath_iter->second);
            if (!out) {
                log::error("{}: Could not open initial output stream to [{}].", __func__, lpath_iter->second);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                    }},
                    // TODO REST API internal error. Do we need REST API error codes to
                    // indicate the issue was not iRODS related (we never reached out to iRODS)?
                    {"http_api_error_code", -1}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                    {"http_api_error_message", "Open error."}
                }.dump();
                res.prepare_payload();
                return res;
            }

            log::trace("{}: Output stream for [{}] is open.", __func__, lpath_iter->second);
            log::trace("{}: Generating transfer handle.", __func__);
            auto transfer_handle = irods::generate_uuid(parallel_write_contexts);
            log::debug("{}: (init) Parallel Write Handle = [{}].", __func__, transfer_handle);

            auto [iter, insertion_result] = parallel_write_contexts.insert({transfer_handle, {.logical_path = lpath_iter->second}});
            log::trace("{}: (init) Checking if parallel_write_context was inserted successfully.", __func__);
            if (!insertion_result) {
                log::error("{}: Could not initialize parallel write context for [{}].", __func__, lpath_iter->second);
                res.body() = json{
                    {"irods_response", {
                        {"error_code", 0} // TODO Need something like IO_OPEN_ERROR
                    }},
                    // TODO REST API internal error. Do we need REST API error codes to
                    // indicate the issue was not iRODS related (we never reached out to iRODS)?
                    {"http_api_error_code", -2}, // IRODS_HTTP_API_ERROR_STREAM_OPEN_FAILED?
                    {"http_api_error_message", "Parallel write initialization error."}
                }.dump();
                res.prepare_payload();
                return res;
            }
            log::trace("{}: (init) parallel_write_context was inserted successfully. Initializing output streams.", __func__);

            // Initialize the first stream.
            auto& streams = iter->second.streams;
            log::trace("{}: (init) Resizing stream container to hold [{}] streams.", __func__, stream_count_iter->second);
            streams.resize(std::stoi(stream_count_iter->second));
#if 0
            streams.push_back(std::move(parallel_write_stream{
                .conn = std::move(conn),
                .tp = std::move(tp)
            }));
#else
            //streams.emplace_back();
            //streams.back().conn = std::move(conn);
            //streams.back().tp = std::move(tp);
            //streams.back().out = {*streams.back().tp, lpath_iter->second};
            log::trace("{}: (init) Initializing stream [0].", __func__);
            streams[0] = std::make_shared<parallel_write_stream>();
            log::trace("{}: (init) Allocated memory for stream [0].", __func__);
            log::trace("{}: (init) Moving client connection into place for stream [0].", __func__);
            streams[0]->conn = std::move(conn);
            log::trace("{}: (init) Moving transport into place for stream [0].", __func__);
            streams[0]->tp = std::move(tp);
            log::trace("{}: (init) Constructing odstream for stream [0].", __func__);
            //streams[0]->out = {*streams.back()->tp, lpath_iter->second};
            //streams[0]->out = {*streams[0]->tp, lpath_iter->second};
            streams[0]->out = std::move(out);
#endif

            if (!streams[0]->out) {
                log::error("{}: (init) Could not open stream [0].", __func__);
                parallel_write_contexts.erase(iter);
                return res;
            }

#if 0
            const auto& replica_token = streams.back()->out.replica_token();
            log::trace("{}: (init) First stream - replica token = [{}].", __func__, replica_token.value);
            const auto& replica_number = streams.back()->out.replica_number();
            log::trace("{}: (init) First stream - replica number = [{}].", __func__, replica_number.value);
#else
            const auto& replica_token = streams[0]->out.replica_token();
            log::debug("{}: (init) First stream - replica token = [{}].", __func__, replica_token.value);
            const auto& replica_number = streams[0]->out.replica_number();
            log::debug("{}: (init) First stream - replica number = [{}].", __func__, replica_number.value);
#endif

            for (auto i = 1ull; i < streams.size(); ++i) {
                log::trace("{}: (init) Initializing stream [{}].", __func__, i);
                log::trace("{}: (init) Initializing client connection for stream [{}].", __func__, i);
                irods::experimental::client_connection sibling_conn;
                log::trace("{}: (init) Initializing transport for stream [{}].", __func__, i);
                auto sibling_tp = std::make_unique<io::client::native_transport>(sibling_conn);
                log::trace("{}: (init) Constructing odstream for stream [{}].", __func__, i);
                io::odstream sibling_out{*sibling_tp, replica_token, lpath_iter->second, replica_number, std::ios::out};

#if 0
                streams.push_back(std::move(parallel_write_stream{
                    .conn = std::move(sibling_conn),
                    .tp = std::move(sibling_tp),
                    .out = std::move(sibling_out)
                }));
#else
                //streams.emplace_back();
                //streams.back().conn = std::move(sibling_conn);
                //streams.back().tp = std::move(sibling_tp);
                //streams.back().out = std::move(sibling_out);
                log::trace("{}: (init) Allocating parallel_write_stream for stream [{}].", __func__, i);
                streams[i] = std::make_shared<parallel_write_stream>();
                log::trace("{}: (init) Moving client connection into parallel_write_stream for stream [{}].", __func__, i);
                streams[i]->conn = std::move(sibling_conn);
                log::trace("{}: (init) Moving transport into parallel_write_stream for stream [{}].", __func__, i);
                streams[i]->tp = std::move(sibling_tp);
                log::trace("{}: (init) Moving odstream into parallel_write_stream for stream [{}].", __func__, i);
                streams[i]->out = std::move(sibling_out);
#endif
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"parallel_write_handle", transfer_handle}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_parallel_write_init_op

    auto handle_parallel_write_shutdown_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            // TODO
            // 1. Verify transfer handle and lookup PTC.
            // 2. Close all streams in reverse order.
            // 3. Disassociate the transfer handle and PTC.
            // 4. Free resources.

            const auto parallel_write_handle_iter = _args.find("parallel-write-handle");
            if (parallel_write_handle_iter == std::end(_args)) {
                log::error("{}: Missing [parallel-write-handle] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            log::debug("{}: (shutdown) Parallel Write Handle = [{}].", __func__, parallel_write_handle_iter->second);

            const auto pw_iter = parallel_write_contexts.find(parallel_write_handle_iter->second);
            if (pw_iter != std::end(parallel_write_contexts)) {
                // Ignore the first stream. It must be closed last so that replication resources
                // are triggered correctly.
                auto end = std::prev(std::rend(pw_iter->second.streams));

                io::on_close_success close_input{};
                close_input.update_size = false;
                close_input.update_status = false;
                close_input.compute_checksum = false;
                close_input.send_notifications = false;
                close_input.preserve_replica_state_table = false;

                for (auto iter = std::rbegin(pw_iter->second.streams); iter != end; ++iter) {
                    (*iter)->out.close(&close_input);
                }

                // Allow the first stream to update the catalog.
                pw_iter->second.streams.front()->out.close();

                parallel_write_contexts.erase(pw_iter);
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_parallel_write_shutdown_op

    auto handle_replicate_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto dst_resc_iter = _args.find("dst-resource");
            if (dst_resc_iter == std::end(_args)) {
                log::error("{}: Missing [dst-resource] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            // TODO This should be part of the replica library.
            DataObjInp input{};
            irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};
            std::strncpy(input.objPath, lpath_iter->second.c_str(), sizeof(DataObjInp::objPath));
            addKeyVal(&input.condInput, DEST_RESC_NAME_KW, dst_resc_iter->second.c_str());

            irods::experimental::client_connection conn;
            const auto ec = rcDataObjRepl(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_replicate_op

    auto handle_trim_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto resc_iter = _args.find("resource");
            if (resc_iter == std::end(_args)) {
                log::error("{}: Missing [resource] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            // TODO This should be part of the replica library.
            DataObjInp input{};
            irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};
            std::strncpy(input.objPath, lpath_iter->second.c_str(), sizeof(DataObjInp::objPath));
            addKeyVal(&input.condInput, RESC_NAME_KW, resc_iter->second.c_str());

            if (const auto iter = _args.find("admin"); iter != std::end(_args) && iter->second == "1") {
                addKeyVal(&input.condInput, ADMIN_KW, "");
            }

            irods::experimental::client_connection conn;
            const auto ec = rcDataObjTrim(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }},
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_trim_op

    auto handle_set_permission_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            irods::experimental::client_connection conn;

            if (!fs::client::is_data_object(conn, lpath_iter->second)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_DATA_OBJECT}
                    }}
                }.dump());
            }

            const auto entity_name_iter = _args.find("entity-name");
            if (entity_name_iter == std::end(_args)) {
                log::error("{}: Missing [entity-name] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto perm_iter = _args.find("permission");
            if (perm_iter == std::end(_args)) {
                log::error("{}: Missing [permission] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto perm_enum = irods::to_permission_enum(perm_iter->second);
            if (!perm_enum) {
                log::error("{}: Invalid value for [permission] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            const auto admin_mode_iter = _args.find("admin");
            if (admin_mode_iter != std::end(_args) && admin_mode_iter->second == "1") {
                fs::client::permissions(fs::admin, conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
            }
            else {
                fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, *perm_enum);
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_set_permission_op

    auto handle_stat_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            irods::experimental::client_connection conn;

            const auto status = fs::client::status(conn, lpath_iter->second);

            if (!fs::client::is_data_object(status)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_DATA_OBJECT}
                    }}
                }.dump());
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

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"type", irods::to_object_type_string(status.type())},
                {"permissions", perms},
                // TODO Should these be returned upon request?
                // What should be included under replicas? Data ID, physical path, replica status, replica number? What else?
                {"replicas", json::array_t{}},
                // TODO Notice these require additional network calls. Could be avoided by using GenQuery, perhaps.
                {"size", fs::client::data_object_size(conn, lpath_iter->second)},
                {"checksum", fs::client::data_object_checksum(conn, lpath_iter->second)},
                {"registered", fs::client::is_data_object_registered(conn, lpath_iter->second)},
                {"mtime", fs::client::last_write_time(conn, lpath_iter->second).time_since_epoch().count()}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_stat_op

    auto handle_register_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
#if 0
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
#endif
    } // handle_register_op

    auto handle_unregister_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
#if 0
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
#else
        (void) _req;
        (void) _args;
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
#endif
    } // handle_unregister_op

    auto handle_remove_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                log::error("{}: Missing [lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            irods::experimental::client_connection conn;

            // TODO This type of check needs to apply to all operations in /data-objects and /collections
            // that take a logical path.
            if (!fs::client::is_data_object(conn, lpath_iter->second)) {
                log::error("{}: Logical path does not point to a data object.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            fs::remove_options opts = fs::remove_options::none;

            if (const auto iter = _args.find("no-trash"); iter != std::end(_args) && iter->second == "1") {
                opts = fs::remove_options::no_trash;
            }

            // There's no admin flag for removal.
            fs::client::remove(conn, lpath_iter->second, opts);
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_remove_op

    auto handle_rename_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto old_lpath_iter = _args.find("old-lpath");
            if (old_lpath_iter == std::end(_args)) {
                log::error("{}: Missing [old-lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            irods::experimental::client_connection conn;

            if (!fs::client::is_data_object(conn, old_lpath_iter->second)) {
                return irods::http::fail(res, http::status::bad_request, json{
                    {"irods_response", {
                        {"error_code", NOT_A_DATA_OBJECT}
                    }}
                }.dump());
            }

            const auto new_lpath_iter = _args.find("new-lpath");
            if (new_lpath_iter == std::end(_args)) {
                log::error("{}: Missing [new-lpath] parameter.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }

            fs::client::rename(conn, old_lpath_iter->second, new_lpath_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_rename_op

    auto handle_touch_op(const irods::http::request_type& _req, const query_arguments_type& _args) -> irods::http::response_type
    {
        const auto result = irods::http::resolve_client_identity(_req);
        if (result.response) {
            return *result.response;
        }

        const auto* client_info = result.client_info;
        log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

        http::response<http::string_body> res{http::status::ok, _req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.keep_alive(_req.keep_alive());

        try {
            const auto lpath_iter = _args.find("lpath");
            if (lpath_iter == std::end(_args)) {
                //if (op_iter->second != "write" && !_args.contains("parallel-write-handle")) {
                    log::error("{}: Missing [lpath] parameter.", __func__);
                    return irods::http::fail(res, http::status::bad_request);
                //}
            }

            json::object_t options;

            auto opt_iter = _args.find("no-create");
            if (opt_iter != std::end(_args)) {
                options["no_create"] = (opt_iter->second == "1");
            }

            opt_iter = _args.find("replica-number");
            if (opt_iter != std::end(_args)) {
                try {
                    options["replica_number"] = std::stoi(opt_iter->second);
                }
                catch (const std::exception& e) {
                    log::error("{}: Could not convert replica-number [{}] into an integer.", __func__, opt_iter->second);
                    return irods::http::fail(res, http::status::bad_request);
                }
            }

            opt_iter = _args.find("leaf-resource");
            if (opt_iter != std::end(_args)) {
                options["leaf_resource_name"] = opt_iter->second;
            }

            opt_iter = _args.find("seconds-since-epoch");
            if (opt_iter != std::end(_args)) {
                try {
                    options["seconds_since_epoch"] = std::stoi(opt_iter->second);
                }
                catch (const std::exception& e) {
                    log::error("{}: Could not convert seconds-since-epoch [{}] into an integer.", __func__, opt_iter->second);
                    return irods::http::fail(res, http::status::bad_request);
                }
            }

            opt_iter = _args.find("reference");
            if (opt_iter != std::end(_args)) {
                options["reference"] = opt_iter->second;
            }

            const json input{
                {"logical_path", lpath_iter->second},
                {"options", options}
            };

            irods::experimental::client_connection conn;
            const auto ec = rc_touch(static_cast<RcComm*>(conn), input.dump().c_str());

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.result(http::status::internal_server_error);
        }

        res.prepare_payload();

        return res;
    } // handle_touch_op
} // anonymous namespace
