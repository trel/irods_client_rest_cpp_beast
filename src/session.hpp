#ifndef IRODS_HTTP_API_SESSION_HPP
#define IRODS_HTTP_API_SESSION_HPP

#include "common.hpp"
#include "log.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/config.hpp>

#include <iterator>
#include <memory>
#include <utility>

namespace irods::http
{
    class session : public std::enable_shared_from_this<session>
    {
      public:
        // Take ownership of the stream
        session(boost::asio::ip::tcp::socket&& socket,
                const request_handler_map_type& _request_handler_map)
            : stream_(std::move(socket))
            //, lambda_(*this)
            , req_handlers_{&_request_handler_map}
        {
        } // session (constructor)

        // Start the asynchronous operation
        auto run() -> void
        {
            // We need to be executing within a strand to perform async operations
            // on the I/O objects in this session. Although not strictly necessary
            // for single-threaded contexts, this example code is written to be
            // thread-safe by default.
            boost::asio::dispatch(stream_.get_executor(),
                                  boost::beast::bind_front_handler(
                                      &session::do_read,
                                      shared_from_this()));
        } // run

        auto do_read() -> void
        {
            // Make the request empty before reading,
            // otherwise the operation behavior is undefined.
            req_ = {};

            // Set the timeout.
            stream_.expires_after(std::chrono::seconds(30)); // TODO Needs to be configurable.

            // Read a request
            boost::beast::http::async_read(stream_, buffer_, req_,
                                           boost::beast::bind_front_handler(
                                               &session::on_read,
                                               shared_from_this()));
        } // do_read

        auto on_read(boost::beast::error_code ec, std::size_t bytes_transferred) -> void
        {
            boost::ignore_unused(bytes_transferred);

            // This means they closed the connection
            if (ec == boost::beast::http::error::end_of_stream) {
                return do_close();
            }

            if (ec) {
                return irods::fail(ec, "read");
            }

            //
            // Process client request and send a response.
            //

            namespace log = irods::http::log;

            // Print the headers.
            for (auto&& h : req_.base()) {
                log::debug("{}: Header: ({}, {})", __func__, h.name_string(), h.value());
            }

            // Print the components of the request URL.
            log::debug("{}: Method: {}", __func__, req_.method_string());
            log::debug("{}: Version: {}", __func__, req_.version());
            log::debug("{}: Target: {}", __func__, req_.target());
            log::debug("{}: Keep Alive: {}", __func__, req_.keep_alive());
            log::debug("{}: Has Content Length: {}", __func__, req_.has_content_length());
            log::debug("{}: Chunked: {}", __func__, req_.chunked());
            log::debug("{}: Needs EOF: {}", __func__, req_.need_eof());

            namespace http = boost::beast::http;

            // "host" is a placeholder that's used so that get_url_path() can parse the URL correctly.
            const auto path = irods::http::get_url_path(fmt::format("http://host{}", req_.target()));
            if (!path) {
                send(irods::http::fail(http::status::bad_request));
            }

            if (const auto iter = req_handlers_->find(*path); iter != std::end(*req_handlers_)) {
                (iter->second)(shared_from_this(), req_);
                return;
            }

            send(irods::http::fail(http::status::not_found));
        } // on_read

        auto on_write(bool close, boost::beast::error_code ec, std::size_t bytes_transferred) -> void
        {
            boost::ignore_unused(bytes_transferred);

            if (ec) {
                return irods::fail(ec, "write");
            }

            if (close) {
                // This means we should close the connection, usually because
                // the response indicated the "Connection: close" semantic.
                return do_close();
            }

            // We're done with the response so delete it
            res_ = nullptr;

            // Read another request
            do_read();
        } // on_write

        auto do_close() -> void
        {
            // Send a TCP shutdown.
            boost::beast::error_code ec;
            stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

            // At this point the connection is closed gracefully.
        } // do_close

        template <bool isRequest, class Body, class Fields>
        auto send(boost::beast::http::message<isRequest, Body, Fields>&& msg) -> void
        {
            namespace beast = boost::beast;
            namespace http  = beast::http;

            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            res_ = sp;

            // Write the response.
            http::async_write(
                stream_,
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    shared_from_this(),
                    sp->need_eof()));
        } // send

      private:
#if 0
        // This is the C++11 equivalent of a generic lambda.
        // The function object is used to send an HTTP message.
        struct send_lambda
        {
            session& self_;

            explicit send_lambda(session& self)
                : self_(self)
            {
            } // send_lambda (constructor)

            template <bool isRequest, class Body, class Fields>
            auto operator()(boost::beast::http::message<isRequest, Body, Fields>&& msg) const -> void
            {
                namespace beast = boost::beast;
                namespace http  = beast::http;

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
            } // operator()()
        }; // struct send_lambda
#endif

        boost::beast::tcp_stream stream_;
        boost::beast::flat_buffer buffer_;
        boost::beast::http::request<boost::beast::http::string_body> req_;
        std::shared_ptr<void> res_;
        //send_lambda lambda_;
        const request_handler_map_type* req_handlers_;
    }; // class session
} // namespace irods::http

#endif // IRODS_HTTP_API_SESSION_HPP
