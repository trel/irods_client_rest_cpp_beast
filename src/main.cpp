#include "common.hpp"
#include "handlers.hpp"
#include "log.hpp"

#include <irods/atomic_apply_metadata_operations.h>
#include <irods/base64.hpp>
#include <irods/client_connection.hpp>
#include <irods/execCmd.h>
#include <irods/execMyRule.h>
#include <irods/filesystem.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_configuration_keywords.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_query.hpp>
#include <irods/msParam.h>
#include <irods/process_stash.hpp>
#include <irods/rcConnect.h>
#include <irods/rcMisc.h>
#include <irods/resource_administration.hpp>
#include <irods/rodsClient.h>
#include <irods/rodsErrorTable.h>
#include <irods/rodsKeyWdDef.h>
#include <irods/ruleExecDel.h>
#include <irods/touch.h>
#include <irods/ticket_administration.hpp>
#include <irods/user_administration.hpp>

#include <irods/transport/default_transport.hpp>
#include <irods/dstream.hpp>

#include <curl/curl.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <string>
#include <string_view>
#include <utility>
#include <unordered_map>
#include <fstream>
#include <span>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace log = irods::http::log;

using response        = http::response<http::string_body>;
using request_handler = std::function<response (const http::request<http::string_body>&)>;

using json = nlohmann::json;

struct url
{
    std::string path;
    std::unordered_map<std::string, std::string> query;
};

struct parallel_write_stream
{
    irods::experimental::client_connection conn{irods::experimental::defer_connection};
    std::unique_ptr<irods::experimental::io::client::native_transport> tp;
    irods::experimental::io::odstream out;
};

struct parallel_write_context
{
    std::string logical_path;
    std::vector<std::shared_ptr<parallel_write_stream>> streams;
};

std::unordered_map<std::string, parallel_write_context> parallel_write_contexts;

auto handle_data_objects(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    std::unordered_map<std::string, std::string> args;

    if (_req.method() == http::verb::get) {
        args = std::move(irods::http::parse_url(_req).query);
    }
    else if (_req.method() == http::verb::post) {
        log::info("{}: body = [{}].", __func__, _req.body());
        args = irods::http::to_argument_list(_req.body());
    }

    const auto op_iter = args.find("op");
    if (op_iter == std::end(args)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::bad_request);
    }

    const auto lpath_iter = args.find("lpath");
    if (lpath_iter == std::end(args)) {
        if (op_iter->second != "write" && !args.contains("parallel-write-handle")) {
            log::error("{}: Missing [lpath] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    namespace io = irods::experimental::io;

    if (op_iter->second == "read") {
        // TODO Inputs:
        // - offset
        // - count
        //     - content-length vs query parameter
        //     - How about chunked encoding?
        //
        // TODO Should a client care about a specific replica when reading?
        // TODO Should a client be allowed to target a leaf resource?

        try {
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
                fmt::print("{}: Could not open data object [{}] for read.\n", __func__, lpath_iter->second);

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
            auto iter = args.find("offset");
            if (iter != std::end(args)) {
                try {
                    in.seekg(std::stoll(iter->second));
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not seek to position [{}] in data object [{}].\n", __func__, iter->second, lpath_iter->second);

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
            iter = args.find("count");
            if (iter != std::end(args)) {
                try {
                    buffer.resize(std::stoi(iter->second));
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not initialize read buffer to size [{}] for data object [{}].\n", __func__, iter->second, lpath_iter->second);

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
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "write") {
        // TODO Inputs:
        // - transfer-handle
        // - offset
        // - count
        //     - content-length vs query parameter
        //     - How about chunked encoding?
        //
        // TODO Should a client care about a specific replica when reading?
        // TODO Should a client be allowed to target a leaf resource?

        try {
            fmt::print("{}: Opening data object [{}] for write.\n", __func__, lpath_iter->second);

            std::unique_ptr<irods::experimental::client_connection> conn;
            std::unique_ptr<io::client::native_transport> tp;

            std::unique_ptr<io::odstream> out;
            io::odstream* out_ptr{};

            const auto parallel_write_handle_iter = args.find("parallel-write-handle"); 
            if (parallel_write_handle_iter != std::end(args)) {
                fmt::print("{}: (write) Parallel Write Handle = [{}].\n", __func__, parallel_write_handle_iter->second);

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
                fmt::print("{}: (write) Parallel Write - stream index = [{}].\n", __func__, idx);
                out_ptr = &iter->second.streams[idx]->out;
                ++idx;
                idx %= iter->second.streams.size();
            }
            else {
                fmt::print("{}: (write) Initializing for single buffer write.\n", __func__);
                conn = std::make_unique<irods::experimental::client_connection>();
                tp = std::make_unique<io::client::native_transport>(*conn);
                out = std::make_unique<io::odstream>(*tp, lpath_iter->second);
                out_ptr = out.get();
            }

            if (!*out_ptr) {
                fmt::print("{}: Could not open data object [{}] for write.\n", __func__, lpath_iter->second);

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
            auto iter = args.find("offset");
            if (iter != std::end(args)) {
                fmt::print("{}: Setting offset for write.\n", __func__);
                try {
                    out_ptr->seekp(std::stoll(iter->second));
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not seek to position [{}] in data object [{}].\n", __func__, iter->second, lpath_iter->second);

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
            iter = args.find("count");
            if (iter == std::end(args)) {
                fmt::print("{}: Missing [count] parameter.\n", __func__);
                res.result(http::status::bad_request);
                res.prepare_payload();
                return res;
            }
            const auto count = std::stoll(std::string{iter->second});

            iter = args.find("bytes");
            if (iter == std::end(args)) {
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
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "parallel-write-init") {
        // TODO
        // 1. Create a parallel transfer context (PTC).
        // 2. Open one iRODS connection per stream and store in the PTC.
        // 3. Generate a transfer handle and associate it with the Bearer/Access token and PTC.
        // 4. Return transfer handle to client.
        //
        // The client is now free to call the write operation as much as they want.

        const auto stream_count_iter = args.find("stream-count");
        if (stream_count_iter == std::end(args)) {
            log::error("{}: Missing [stream-count] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        namespace io = irods::experimental::io;

        fmt::print("{}: Opening initial output stream to [{}].\n", __func__, lpath_iter->second);

        // Open the first stream.
        irods::experimental::client_connection conn;
        auto tp = std::make_unique<io::client::native_transport>(conn);
        io::odstream out{*tp, lpath_iter->second};

        fmt::print("{}: Checking if output stream is open for [{}].\n", __func__, lpath_iter->second);
        if (!out) {
            fmt::print("{}: Could not open initial output stream to [{}].\n", __func__, lpath_iter->second);
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

        fmt::print("{}: Output stream for [{}] is open.\n", __func__, lpath_iter->second);
        fmt::print("{}: Generating transfer handle.\n", __func__);
        auto transfer_handle = irods::generate_uuid(parallel_write_contexts);
        fmt::print("{}: (init) Parallel Write Handle = [{}].\n", __func__, transfer_handle);

        auto [iter, insertion_result] = parallel_write_contexts.insert({transfer_handle, {.logical_path = lpath_iter->second}});
        fmt::print("{}: (init) Checking if parallel_write_context was inserted successfully.\n", __func__);
        if (!insertion_result) {
            fmt::print("{}: Could not initialize parallel write context for [{}].\n", __func__, lpath_iter->second);
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
        fmt::print("{}: (init) parallel_write_context was inserted successfully. Initializing output streams.\n", __func__);

        // Initialize the first stream.
        auto& streams = iter->second.streams;
        fmt::print("{}: (init) Resizing stream container to hold [{}] streams.\n", __func__, stream_count_iter->second);
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
        fmt::print("{}: (init) Initializing stream [0].\n", __func__);
        streams[0] = std::make_shared<parallel_write_stream>();
        fmt::print("{}: (init) Allocated memory for stream [0].\n", __func__);
        fmt::print("{}: (init) Moving client connection into place for stream [0].\n", __func__);
        streams[0]->conn = std::move(conn);
        fmt::print("{}: (init) Moving transport into place for stream [0].\n", __func__);
        streams[0]->tp = std::move(tp);
        fmt::print("{}: (init) Constructing odstream for stream [0].\n", __func__);
        //streams[0]->out = {*streams.back()->tp, lpath_iter->second};
        //streams[0]->out = {*streams[0]->tp, lpath_iter->second};
        streams[0]->out = std::move(out);
#endif

        if (!streams[0]->out) {
            fmt::print("{}: (init) Could not open stream [0].\n", __func__);
            parallel_write_contexts.erase(iter);
            http::response<http::string_body> res{http::status::ok, _req.version()};
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, "text/plain");
            res.set(http::field::content_length, "0");
            res.keep_alive(_req.keep_alive());
            return res;
        }

#if 0
        const auto& replica_token = streams.back()->out.replica_token();
        fmt::print("{}: (init) First stream - replica token = [{}].\n", __func__, replica_token.value);
        const auto& replica_number = streams.back()->out.replica_number();
        fmt::print("{}: (init) First stream - replica number = [{}].\n", __func__, replica_number.value);
#else
        const auto& replica_token = streams[0]->out.replica_token();
        fmt::print("{}: (init) First stream - replica token = [{}].\n", __func__, replica_token.value);
        const auto& replica_number = streams[0]->out.replica_number();
        fmt::print("{}: (init) First stream - replica number = [{}].\n", __func__, replica_number.value);
#endif

        for (auto i = 1ull; i < streams.size(); ++i) {
            fmt::print("{}: (init) Initializing stream [{}].\n", __func__, i);
            fmt::print("{}: (init) Initializing client connection for stream [{}].\n", __func__, i);
            irods::experimental::client_connection sibling_conn;
            fmt::print("{}: (init) Initializing transport for stream [{}].\n", __func__, i);
            auto sibling_tp = std::make_unique<io::client::native_transport>(sibling_conn);
            fmt::print("{}: (init) Constructing odstream for stream [{}].\n", __func__, i);
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
            fmt::print("{}: (init) Allocating parallel_write_stream for stream [{}].\n", __func__, i);
            streams[i] = std::make_shared<parallel_write_stream>();
            fmt::print("{}: (init) Moving client connection into parallel_write_stream for stream [{}].\n", __func__, i);
            streams[i]->conn = std::move(sibling_conn);
            fmt::print("{}: (init) Moving transport into parallel_write_stream for stream [{}].\n", __func__, i);
            streams[i]->tp = std::move(sibling_tp);
            fmt::print("{}: (init) Moving odstream into parallel_write_stream for stream [{}].\n", __func__, i);
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
    else if (op_iter->second == "parallel-write-shutdown") {
        // TODO
        // 1. Verify transfer handle and lookup PTC.
        // 2. Close all streams in reverse order.
        // 3. Disassociate the transfer handle and PTC.
        // 4. Free resources.

        const auto parallel_write_handle_iter = args.find("parallel-write-handle");
        if (parallel_write_handle_iter == std::end(args)) {
            log::error("{}: Missing [parallel-write-handle] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        fmt::print("{}: (shutdown) Parallel Write Handle = [{}].\n", __func__, parallel_write_handle_iter->second);

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
    else if (op_iter->second == "replicate") {
        const auto dst_resc_iter = args.find("dst-resource");
        if (dst_resc_iter == std::end(args)) {
            log::error("{}: Missing [dst-resource] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
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
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", "An unexpected error occurred while processing the request."}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "trim") {
        const auto resc_iter = args.find("resource");
        if (resc_iter == std::end(args)) {
            log::error("{}: Missing [resource] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            // TODO This should be part of the replica library.
            DataObjInp input{};
            irods::at_scope_exit free_memory{[&input] { clearKeyVal(&input.condInput); }};
            std::strncpy(input.objPath, lpath_iter->second.c_str(), sizeof(DataObjInp::objPath));
            addKeyVal(&input.condInput, RESC_NAME_KW, resc_iter->second.c_str());

            if (const auto iter = args.find("admin"); iter != std::end(args) && iter->second == "1") {
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
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", "An unexpected error occurred while processing the request."}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "set-permission") {
        const auto entity_name_iter = args.find("entity-name");
        if (entity_name_iter == std::end(args)) {
            log::error("{}: Missing [entity-name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        const auto perm_iter = args.find("permission");
        if (perm_iter == std::end(args)) {
            log::error("{}: Missing [permission] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        namespace fs = irods::experimental::filesystem;

        try {
            irods::experimental::client_connection conn;

            const auto admin_mode_iter = args.find("admin");
            if (admin_mode_iter != std::end(args) && admin_mode_iter->second == "1") {
                fs::client::permissions(fs::admin, conn, lpath_iter->second, entity_name_iter->second, fs::perms::own);
            }
            else {
                fs::client::permissions(conn, lpath_iter->second, entity_name_iter->second, fs::perms::own);
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "stat") {
        namespace fs = irods::experimental::filesystem;

        try {
            irods::experimental::client_connection conn;
            const auto status = fs::client::status(conn, lpath_iter->second);

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
                {"checksum", fs::client::data_object_checksum(conn, lpath_iter->second)}
            }.dump();
        }
        catch (const fs::filesystem_error& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", "An unexpected error occurred while processing the request."}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "register") {
        // TODO Notes:
        // - Physical path is set via FILE_PATH_KW
        // - Destination resource is set via DEST_RESC_NAME_KW
        // - Registering a "replica" requires setting REG_REPL_KW
        // - Must be on the server unless the data size is provided (DATA_SIZE_KW)
        // - Must support checksums and verification (i.e. REG_CHKSUM_KW, VERIFY_CHKSUM_KW)
        // - Must support the force flag (i.e. FORCE_FLAG_KW)
        // - Can't support collections and recursive flag
        //
        // See regUtil.cpp for more details.
    }
    else if (op_iter->second == "unregister") {
        // TODO So we don't have a dedicated API for this. Unregistering replicas feels like it should
        // be a real API. iunreg relies on trimUtil() and rmUtil() to do its job.
    }
    else if (op_iter->second == "remove") {
        namespace fs = irods::experimental::filesystem;

        try {
            irods::experimental::client_connection conn;

            // TODO This type of check needs to apply to all operations in /data-objects and /collections
            // that take a logical path.
            if (!fs::client::is_data_object(conn, lpath_iter->second)) {
                log::error("{}: Logical path does not point to a data object.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            fs::remove_options opts = fs::remove_options::none;

            if (const auto iter = args.find("no-trash"); iter != std::end(args) && iter->second == "1") {
                opts = fs::remove_options::no_trash;
            }

            // There's no admin flag for removal.
            fs::client::remove(conn, lpath_iter->second, opts);
        }
        catch (const fs::filesystem_error& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code().value()},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "touch") {
        try {
            json::object_t options;

            auto opt_iter = args.find("no-create");
            if (opt_iter != std::end(args)) {
                options["no_create"] = (opt_iter->second == "1");
            }

            opt_iter = args.find("replica-number");
            if (opt_iter != std::end(args)) {
                try {
                    options["replica_number"] = std::stoi(opt_iter->second);
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not convert replica-number [{}] into an integer.", __func__, opt_iter->second);
                }
            }

            opt_iter = args.find("leaf-resource");
            if (opt_iter != std::end(args)) {
                options["leaf_resource_name"] = opt_iter->second;
            }

            opt_iter = args.find("seconds-since-epoch");
            if (opt_iter != std::end(args)) {
                try {
                    options["seconds_since_epoch"] = std::stoi(opt_iter->second);
                }
                catch (const std::exception& e) {
                    fmt::print("{}: Could not convert seconds-since-epoch [{}] into an integer.", __func__, opt_iter->second);
                }
            }

            opt_iter = args.find("reference");
            if (opt_iter != std::end(args)) {
                options["reference"] = opt_iter->second;
            }

            const json input{
                {"logical_path", lpath_iter->second.c_str()},
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
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_metadata(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::post) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    // Decode the body of the POST request.
    // It will contain the JSON data representing the metadata operations to apply.
    //
    // TODO Any handler operations that can result in the catalog changing will need to
    // be updated to require POST. The function below is key to supporting this because
    // it splits the body of the request into key-value pairs and then decodes the values
    // so they can be sent to iRODS.
    const auto args = irods::http::to_argument_list(_req.body());

    const auto op_iter = args.find("op");
    if (op_iter == std::end(args)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::bad_request);
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    // TODO This atomic metadata endpoint feels like it should be part of the other endpoints
    // rather than its own. Consider merging it. If it is merged, the command can become the
    // following:
    //
    //     /data-objects?op=apply_metadata_operations
    //
    // However, this one endpoint already covers all iRODS entities.
    if (op_iter->second == "atomic_execute") {
        try {
            const auto data_iter = args.find("data");
            if (data_iter == std::end(args)) {
                log::error("{}: Missing [data] parameter.", __func__);
                return irods::http::fail(http::status::bad_request);
            }

            char* output{};
            irods::at_scope_exit_unsafe free_output{[&output] { std::free(output); }};

            irods::experimental::client_connection conn;
            const auto ec = rc_atomic_apply_metadata_operations(static_cast<RcComm*>(conn), data_iter->second.c_str(), &output);

            json error_info;
            if (output) {
                error_info = json::parse(output);
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec}
                }},
                {"error_info", error_info}
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_query(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = irods::http::parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::bad_request);
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    if (op_iter->second == "execute") {
        const auto query_iter = url.query.find("query");
        if (query_iter == std::end(url.query)) {
            log::error("{}: Missing [query] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }
#if 0
        const auto query_type_iter = url.query.find("query-type");
        if (query_type_iter != std::end(url.query)) {
            log::error("{}: Missing [query-type] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }
#endif
        // TODO GenQuery2 is definitely the right answer for this simply because of
        // pagination features such as OFFSET and LIMIT. We can make that a runtime
        // configuration option.

        try {
            irods::experimental::client_connection conn;

            json::array_t row;
            json::array_t rows;

            for (auto&& r : irods::query{static_cast<RcComm*>(conn), query_iter->second}) {
                for (auto&& c : r) {
                    row.push_back(c);
                }

                rows.push_back(row);
                row.clear();
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"rows", rows}
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "list_genquery_columns") {
        // TODO GenQuery2 doesn't expose these. Perhaps the REST API doesn't need to either.
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    }
    else if (op_iter->second == "list_specific_queries") {
        // TODO Look at iquest's implementation.
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    }
    else {
        fmt::print("{}: Invalid operator [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_resources(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = irods::http::parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    namespace ia = irods::experimental::administration;

    if (op_iter->second == "create") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        const auto type_iter = url.query.find("type");
        if (type_iter == std::end(url.query)) {
            log::error("{}: Missing [type] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            ia::resource_registration_info resc_info;
            resc_info.resource_name = name_iter->second;
            resc_info.resource_type = type_iter->second;

            const auto host_iter = url.query.find("host");
            if (host_iter != std::end(url.query)) {
                resc_info.host_name = host_iter->second;
            }

            const auto vault_path_iter = url.query.find("vault-path");
            if (vault_path_iter != std::end(url.query)) {
                resc_info.vault_path = vault_path_iter->second;
            }

            const auto ctx_iter = url.query.find("context");
            if (ctx_iter != std::end(url.query)) {
                resc_info.context_string = ctx_iter->second;
            }

            irods::experimental::client_connection conn;
            ia::client::add_resource(conn, resc_info);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::remove_resource(conn, name_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "modify") {
        // TODO
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    }
    else if (op_iter->second == "stat") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;

            json::object_t info;
            bool exists = false;

            if (const auto resc = ia::client::resource_info(conn, name_iter->second); resc) {
                exists = true;

                info = { // TODO Can't use += yet :-(
                    {"id", resc->id()},
                    {"name", resc->name()},
                    {"type", resc->type()},
                    {"zone", resc->zone_name()},
                    {"host", resc->host_name()},
                    {"vault_path", resc->vault_path()},
                    {"status", resc->status()},
                    {"context", resc->context_string()},
                    {"comments", resc->comments()},
                    {"information", resc->information()},
                    {"free_space", resc->free_space()},
                    {"free_space_last_modified", resc->free_space_last_modified().time_since_epoch().count()},
                    {"parent_id", resc->parent_id()},
                    {"created", resc->created().time_since_epoch().count()},
                    {"last_modified", resc->last_modified().time_since_epoch().count()}
                };
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"exists", exists},
                {"info", info}
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "add_child") {
        const auto parent_name_iter = url.query.find("parent-name");
        if (parent_name_iter == std::end(url.query)) {
            log::error("{}: Missing [parent-name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        const auto child_name_iter = url.query.find("child-name");
        if (child_name_iter == std::end(url.query)) {
            log::error("{}: Missing [child-name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;

            const auto ctx_iter = url.query.find("context");
            if (ctx_iter != std::end(url.query)) {
                ia::client::add_child_resource(conn, parent_name_iter->second, child_name_iter->second, ctx_iter->second);
            }
            else {
                ia::client::add_child_resource(conn, parent_name_iter->second, child_name_iter->second);
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove_child") {
        const auto parent_name_iter = url.query.find("parent-name");
        if (parent_name_iter == std::end(url.query)) {
            log::error("{}: Missing [parent-name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        const auto child_name_iter = url.query.find("child-name");
        if (child_name_iter == std::end(url.query)) {
            log::error("{}: Missing [child-name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::remove_child_resource(conn, parent_name_iter->second, child_name_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "rebalance") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::rebalance_resource(conn, name_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
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
            res.result(http::status::bad_request);
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operator [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_rules(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = irods::http::parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::bad_request);
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    if (op_iter->second == "execute") {
        // TODO Wrap all of this in a try-catch block.

        const auto rule_text_iter = url.query.find("rule-text");
        if (rule_text_iter == std::end(url.query)) {
            log::error("{}: Missing [rule-text] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        ExecMyRuleInp input{};

        irods::at_scope_exit clear_kvp{[&input] {
            clearKeyVal(&input.condInput);
            clearMsParamArray(input.inpParamArray, 0); // 0 -> do not free external structure.
        }};

        const auto rule_text = fmt::format("@external rule {{ {} }}", rule_text_iter->second);
        std::strncpy(input.myRule, rule_text.c_str(), sizeof(ExecMyRuleInp::myRule));

        const auto rep_instance_iter = url.query.find("rep-instance");
        if (rep_instance_iter != std::end(url.query)) {
            addKeyVal(&input.condInput, irods::KW_CFG_INSTANCE_NAME, rep_instance_iter->second.c_str());
        }

        MsParamArray param_array{};
        input.inpParamArray = &param_array; // TODO Need to accept INPUT params.
        std::strncpy(input.outParamDesc, "ruleExecOut", sizeof(input.outParamDesc)); // TODO Need to accept OUTPUT params.

        MsParamArray* out_param_array{};

        json stdout_output;
        json stderr_output;

        irods::experimental::client_connection conn;
        const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array);

        if (ec >= 0) {
            if (auto* msp = getMsParamByType(out_param_array, ExecCmdOut_MS_T); msp) {
                if (const auto* exec_out = static_cast<ExecCmdOut*>(msp->inOutStruct); exec_out) {
                    if (exec_out->stdoutBuf.buf) {
                        stdout_output = static_cast<const char*>(exec_out->stdoutBuf.buf);
                        fmt::print("{}: stdout_output = [{}]\n", __func__, stdout_output.get_ref<const std::string&>());
                    }

                    if (exec_out->stderrBuf.buf) {
                        stderr_output = static_cast<const char*>(exec_out->stderrBuf.buf);
                        fmt::print("{}: stderr_output = [{}]\n", __func__, stderr_output.get_ref<const std::string&>());
                    }
                }
            }

            if (auto* msp = getMsParamByLabel(out_param_array, "ruleExecOut"); msp) {
                fmt::print("{}: ruleExecOut = [{}]\n", __func__, (char*) msp->inOutStruct);
            }
        }

        // TODO Probably not needed.
        //printErrorStack(static_cast<RcComm*>(conn)->rError);

        res.body() = json{
            {"irods_response", {
                {"error_code", ec},
            }},
            {"stdout", stdout_output},
            {"stderr", stderr_output}
        }.dump();
    }
    else if (op_iter->second == "remove_delay_rule") {
        const auto rule_id_iter = url.query.find("rule-id");
        if (rule_id_iter == std::end(url.query)) {
            log::error("{}: Missing [rule-id] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            RuleExecDeleteInput input{};
            std::strncpy(input.ruleExecId, rule_id_iter->second.c_str(), sizeof(RuleExecDeleteInput::ruleExecId));

            irods::experimental::client_connection conn;
            const auto ec = rcRuleExecDel(static_cast<RcComm*>(conn), &input);

            res.body() = json{
                {"irods_response", {
                    {"error_code", ec},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "modify_delay_rule") {
        // TODO
        log::error("{}: Operation not implemented.", __func__);
        return irods::http::fail(http::status::not_implemented);
    }
    else if (op_iter->second == "list_rule_engines") {
        ExecMyRuleInp input{};

        irods::at_scope_exit clear_kvp{[&input] {
            clearKeyVal(&input.condInput);
            clearMsParamArray(input.inpParamArray, 0); // 0 -> do not free external structure.
        }};

        addKeyVal(&input.condInput, AVAILABLE_KW, "");

        MsParamArray param_array{};
        input.inpParamArray = &param_array;

        MsParamArray* out_param_array{};

        irods::experimental::client_connection conn;

        const auto ec = rcExecMyRule(static_cast<RcComm*>(conn), &input, &out_param_array);

        std::vector<std::string> plugin_instances;

        if (ec >= 0) {
            if (const auto* es = static_cast<RcComm*>(conn)->rError; es && es->len > 0) {
                boost::split(plugin_instances, es->errMsg[0]->msg, boost::is_any_of("\n"));
            }

            plugin_instances.erase(std::begin(plugin_instances)); // Remove unnecessary header.
            plugin_instances.pop_back(); // Remove empty line as a result of splitting the string via a newline.

            // Remove leading and trailing whitespace.
            std::for_each(std::begin(plugin_instances), std::end(plugin_instances), [](auto& _v) { boost::trim(_v); });
        }

        res.body() = json{
            {"irods_response", {
                {"error_code", ec},
            }},
            {"rule_engine_plugin_instances", plugin_instances},
        }.dump();
    }
    else if (op_iter->second == "list_delay_rules") {
        const auto all_rules_iter = url.query.find("all-rules");
        if (all_rules_iter != std::end(url.query)) {
            // TODO
            //log::error("{}: Operation not implemented.", __func__);
            //return irods::http::fail(http::status::not_implemented);
        }

        try {
            const auto gql = fmt::format(
                "select "
                "RULE_EXEC_ID, "
                "RULE_EXEC_NAME, "
                "RULE_EXEC_REI_FILE_PATH, "
                "RULE_EXEC_USER_NAME, "
                "RULE_EXEC_ADDRESS, "
                "RULE_EXEC_TIME, "
                "RULE_EXEC_FREQUENCY, "
                "RULE_EXEC_PRIORITY, "
                "RULE_EXEC_ESTIMATED_EXE_TIME, "
                "RULE_EXEC_NOTIFICATION_ADDR, "
                "RULE_EXEC_LAST_EXE_TIME, "
                "RULE_EXEC_STATUS, "
#if 0
                "RULE_EXEC_CONTEXT "
                "where RULE_EXEC_USER_NAME = '{}'",
                *username);
#else
                "RULE_EXEC_CONTEXT");
#endif

            json::array_t row;
            json::array_t rows;

            irods::experimental::client_connection conn;

            for (auto&& r : irods::query{static_cast<RcComm*>(conn), gql}) {
                for (auto&& c : r) {
                    row.push_back(c);
                }

                rows.push_back(row);
                row.clear();
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"rows", rows}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_users_groups(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = irods::http::parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::bad_request);
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    namespace ia = irods::experimental::administration;

    if (op_iter->second == "create_user") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        const auto zone_iter = url.query.find("zone");
        if (zone_iter == std::end(url.query)) {
            log::error("{}: Missing [zone] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        auto user_type = ia::user_type::rodsuser;
        const auto user_type_iter = url.query.find("user-type");
        if (user_type_iter != std::end(url.query) && user_type_iter->second != "rodsuser") {
            if (user_type_iter->second == "rodsadmin") {
                user_type = ia::user_type::rodsadmin;
            }
            else if (user_type_iter->second == "groupadmin") {
                user_type = ia::user_type::groupadmin;
            }
            else {
                log::error("{}: Invalid user-type.", __func__);
                return irods::http::fail(res, http::status::bad_request);
            }
        }

        // TODO This can be derived if the REST API provides a way to know what zone it
        // is connected to. For example, the config file can define the local zone and then
        // we can use that to compare whether the client is attempting to create a local or
        // remote user.
        auto zone_type = ia::zone_type::local;
        const auto remote_iter = url.query.find("remote_user");
        if (remote_iter != std::end(url.query) && remote_iter->second == "1") {
            zone_type = ia::zone_type::remote;
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::add_user(conn, ia::user{name_iter->second, zone_iter->second}, user_type, zone_type);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove_user") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        const auto zone_iter = url.query.find("zone");
        if (zone_iter == std::end(url.query)) {
            log::error("{}: Missing [zone] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::remove_user(conn, ia::user{name_iter->second, zone_iter->second});

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "set_password") {
        // TODO
    }
    else if (op_iter->second == "set_user_type") {
        // TODO
    }
    else if (op_iter->second == "add_user_auth") {
        // TODO
    }
    else if (op_iter->second == "remove_user_auth") {
        // TODO
    }
    else if (op_iter->second == "create_group") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::add_group(conn, ia::group{name_iter->second});

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove_group") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::client::remove_group(conn, ia::group{name_iter->second});

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "add_to_group") {
        const auto user_iter = url.query.find("user");
        if (user_iter == std::end(url.query)) {
            log::error("{}: Missing [user] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        const auto group_iter = url.query.find("group");
        if (group_iter == std::end(url.query)) {
            log::error("{}: Missing [group] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;

            const auto zone_iter = url.query.find("zone");
            if (zone_iter != std::end(url.query)) {
                ia::client::add_user_to_group(conn, ia::group{group_iter->second}, ia::user{user_iter->second, zone_iter->second});
            }
            else {
                ia::client::add_user_to_group(conn, ia::group{group_iter->second}, ia::user{user_iter->second});
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove_from_group") {
        const auto user_iter = url.query.find("user");
        if (user_iter == std::end(url.query)) {
            log::error("{}: Missing [user] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        const auto group_iter = url.query.find("group");
        if (group_iter == std::end(url.query)) {
            log::error("{}: Missing [group] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;

            const auto zone_iter = url.query.find("zone");
            if (zone_iter != std::end(url.query)) {
                ia::client::remove_user_from_group(conn, ia::group{group_iter->second}, ia::user{user_iter->second, zone_iter->second});
            }
            else {
                ia::client::remove_user_from_group(conn, ia::group{group_iter->second}, ia::user{user_iter->second});
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "users") {
        try {
            irods::experimental::client_connection conn;
            const auto users = ia::client::users(conn);

            std::vector<json> v;
            v.reserve(users.size());

            for (auto&& u : users) {
                v.push_back({
                    {"name", u.name},
                    {"zone", u.zone}
                });
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }},
                {"users", v}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "groups") {
        try {
            irods::experimental::client_connection conn;
            auto groups = ia::client::groups(conn);

            std::vector<std::string> v;
            v.reserve(groups.size());

            for (auto&& g : groups) {
                v.push_back(std::move(g.name));
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0}
                }},
                {"groups", v}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "members") {
        // TODO
    }
    else if (op_iter->second == "is_member_of_group") {
        // TODO
    }
    else if (op_iter->second == "stat") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;

            json info{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"exists", false}
            };

            // If the zone parameter is provided, we're likely dealing with a user. Otherwise,
            // we don't know what we're identifying.
            const auto zone_iter = url.query.find("zone");
            if (zone_iter != std::end(url.query)) {
                const ia::user user{name_iter->second, zone_iter->second};
                if (const auto id = ia::client::id(conn, user); id) {
                    info.update({
                        {"exists", true},
                        {"id", *id},
                        {"type", ia::to_c_str(*ia::client::type(conn, user))}
                    });
                }

                res.body() = info.dump();
                res.prepare_payload();
                return res;
            }

            // The client did not include a zone so we are required to test if the name
            // identifies a user or group.

            const ia::user user{name_iter->second};
            if (const auto id = ia::client::id(conn, user); id) {
                info.update({
                    {"exists", true},
                    {"id", *id},
                    {"local_unique_name", ia::client::local_unique_name(conn, user)},
                    {"type", ia::to_c_str(*ia::client::type(conn, user))}
                });
            }

            const ia::group group{name_iter->second};
            if (const auto id = ia::client::id(conn, group); id) {
                info.update({
                    {"exists", true},
                    {"id", *id},
                    {"type", "rodsgroup"}
                });
            }

            res.body() = info.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

auto handle_tickets(const http::request<http::string_body>& _req) -> http::response<http::string_body>
{
    if (_req.method() != http::verb::get && _req.method() != http::verb::post) {
        log::error("{}: Incorrect HTTP method.", __func__);
        return irods::http::fail(http::status::method_not_allowed);
    }

    const auto result = irods::http::resolve_client_identity(_req);
    if (result.response) {
        return *result.response;
    }

    const auto* client_info = result.client_info;
    log::info("{}: client_info = ({}, {})", __func__, client_info->username, client_info->password);

    //
    // At this point, we know the user has authorization to perform this operation.
    //

    const auto url = irods::http::parse_url(_req);

    const auto op_iter = url.query.find("op");
    if (op_iter == std::end(url.query)) {
        log::error("{}: Missing [op] parameter.", __func__);
        return irods::http::fail(http::status::bad_request);
    }

    http::response<http::string_body> res{http::status::ok, _req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(_req.keep_alive());

    namespace ia = irods::experimental::administration;

    if (op_iter->second == "create") {
        const auto lpath_iter = url.query.find("lpath");
        if (lpath_iter == std::end(url.query)) {
            log::error("{}: Missing [lpath] parameter.", __func__);
            return irods::http::fail(http::status::bad_request);
        }

        try {
            auto ticket_type = ia::ticket::ticket_type::read;
            const auto type_iter = url.query.find("type");
            if (type_iter != std::end(url.query)) {
                if (type_iter->second == "write") {
                    ticket_type = ia::ticket::ticket_type::write;
                }
                else if (type_iter->second != "read") {
                    log::error("{}: Missing [type] parameter.", __func__);
                    return irods::http::fail(http::status::bad_request);
                }
            }

            irods::experimental::client_connection conn;
            const auto ticket = ia::ticket::client::create_ticket(conn, ticket_type, lpath_iter->second);

            auto constraint_iter = url.query.find("use-count");
            if (constraint_iter != std::end(url.query)) {
                const auto count = std::stoi(constraint_iter->second);
                ia::ticket::client::set_ticket_constraint(conn, ticket, ia::ticket::use_count_constraint{count});
            }
            else {
                ia::ticket::client::set_ticket_constraint(conn, ticket, ia::ticket::use_count_constraint{0});
            }

            constraint_iter = url.query.find("write-data-object-count");
            if (constraint_iter != std::end(url.query)) {
                const auto count = std::stoi(constraint_iter->second);
                ia::ticket::client::set_ticket_constraint(conn, ticket, ia::ticket::n_writes_to_data_object_constraint{count});
            }
            else {
                ia::ticket::client::set_ticket_constraint(conn, ticket, ia::ticket::n_writes_to_data_object_constraint{0});
            }

            constraint_iter = url.query.find("write-byte-count");
            if (constraint_iter != std::end(url.query)) {
                const auto count = std::stoi(constraint_iter->second);
                ia::ticket::client::set_ticket_constraint(conn, ticket, ia::ticket::n_write_bytes_constraint{count});
            }
            else {
                ia::ticket::client::set_ticket_constraint(conn, ticket, ia::ticket::n_write_bytes_constraint{0});
            }

            constraint_iter = url.query.find("seconds-until-expiration");
            if (constraint_iter != std::end(url.query)) {
                // TODO Not yet supported by the ticket administration library.
            }

            constraint_iter = url.query.find("users");
            if (constraint_iter != std::end(url.query)) {
                std::vector<std::string> users;
                boost::split(users, constraint_iter->second, boost::is_any_of(","));
                for (const auto& user : users) {
                    ia::ticket::client::add_ticket_constraint(conn, ticket, ia::ticket::user_constraint{user});
                }
            }

            constraint_iter = url.query.find("groups");
            if (constraint_iter != std::end(url.query)) {
                std::vector<std::string> groups;
                boost::split(groups, constraint_iter->second, boost::is_any_of(","));
                for (const auto& group : groups) {
                    ia::ticket::client::add_ticket_constraint(conn, ticket, ia::ticket::group_constraint{group});
                }
            }

            constraint_iter = url.query.find("hosts");
            if (constraint_iter != std::end(url.query)) {
                std::vector<std::string> hosts;
                boost::split(hosts, constraint_iter->second, boost::is_any_of(","));
                for (const auto& host : hosts) {
                    ia::ticket::client::add_ticket_constraint(conn, ticket, ia::ticket::host_constraint{host});
                }
            }

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }},
                {"ticket", ticket}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else if (op_iter->second == "remove") {
        const auto name_iter = url.query.find("name");
        if (name_iter == std::end(url.query)) {
            log::error("{}: Missing [name] parameter.", __func__);
            return irods::http::fail(res, http::status::bad_request);
        }

        try {
            irods::experimental::client_connection conn;
            ia::ticket::client::delete_ticket(conn, name_iter->second);

            res.body() = json{
                {"irods_response", {
                    {"error_code", 0},
                }}
            }.dump();
        }
        catch (const irods::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", e.code()},
                    {"error_message", e.client_display_what()}
                }}
            }.dump();
        }
        catch (const std::exception& e) {
            res.body() = json{
                {"irods_response", {
                    {"error_code", SYS_LIBRARY_ERROR},
                    {"error_message", e.what()}
                }}
            }.dump();
        }
    }
    else {
        fmt::print("{}: Invalid operation [{}].\n", __func__, op_iter->second);
        res.result(http::status::bad_request);
    }

    res.prepare_payload();

    return res;
}

const std::unordered_map<std::string_view, request_handler> req_handlers{
    {"/irods-rest/0.9.5/authenticate", irods::http::handler::authentication},
    {"/irods-rest/0.9.5/collections",  irods::http::handler::collections},
    //{"/irods-rest/0.9.5/config",       "/config"},
    {"/irods-rest/0.9.5/data-objects", handle_data_objects},
    {"/irods-rest/0.9.5/metadata",     handle_metadata},
    {"/irods-rest/0.9.5/query",        handle_query},
    {"/irods-rest/0.9.5/resources",    handle_resources},
    {"/irods-rest/0.9.5/rules",        handle_rules},
    {"/irods-rest/0.9.5/tickets",      handle_tickets},
    {"/irods-rest/0.9.5/users-groups", handle_users_groups},
    //{"/irods-rest/0.9.5/zones",        "/zones"}
};

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template <class Body, class Allocator, class Send>
auto handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send) -> void
{
    // Print the headers.
    for (auto&& h : req.base()) {
        log::debug("{}: Header: ({}, {})", __func__, h.name_string(), h.value());
    }

    // Print the components of the request URL.
    log::debug("{}: Method: {}", __func__, req.method_string());
    log::debug("{}: Version: {}", __func__, req.version());
    log::debug("{}: Target: {}", __func__, req.target());
    log::debug("{}: Keep Alive: {}", __func__, req.keep_alive());
    log::debug("{}: Has Content Length: {}", __func__, req.has_content_length());
    log::debug("{}: Chunked: {}", __func__, req.chunked());
    log::debug("{}: Needs EOF: {}", __func__, req.need_eof());

    // "host" is used so that get_url_path() can parse the URL.
    const auto path = irods::http::get_url_path(fmt::format("http://host{}", req.target()));
    if (!path) {
        send(std::move(irods::http::fail(http::status::bad_request)));
    }

    if (const auto iter = req_handlers.find(*path); iter != std::end(req_handlers)) {
        send((iter->second)(req));
        return;
    }

    send(std::move(irods::http::fail(http::status::not_found)));
}

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session>
{
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self)
            : self_(self)
        {
        }

        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg) const
        {
            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.stream_,
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    self_.shared_from_this(),
                    sp->need_eof()));
        }
    };

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

public:
    // Take ownership of the stream
    session(tcp::socket&& socket)
        : stream_(std::move(socket))
        , lambda_(*this)
    {
    }

    // Start the asynchronous operation
    void
    run()
    {
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session. Although not strictly necessary
        // for single-threaded contexts, this example code is written to be
        // thread-safe by default.
        net::dispatch(stream_.get_executor(),
                      beast::bind_front_handler(
                          &session::do_read,
                          shared_from_this()));
    }

    void
    do_read()
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return do_close();

        if(ec)
            return fail(ec, "read");

        // Send the response
        handle_request(std::move(req_), lambda_);
    }

    void
    on_write(
        bool close,
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }

    void
    do_close()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;

public:
    listener(net::io_context& ioc, tcp::endpoint endpoint)
        : ioc_(ioc)
        , acceptor_(net::make_strand(ioc))
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if (ec) {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }

        // Create the session and run it
        std::make_shared<session>(std::move(socket))->run();

        // Accept another connection
        do_accept();
    }
};

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    // Check command line arguments.
    if (argc != 4) {
        std::cerr <<
            "Usage: http-server-async <address> <port> <threads>\n" <<
            "Example:\n" <<
            "    http-server-async 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }

    load_client_api_plugins();

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[3]));

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // Create and launch a listening port
    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    return EXIT_SUCCESS;
}
