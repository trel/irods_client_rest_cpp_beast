#ifndef IRODS_HTTP_API_CRLF_PARSER_HPP
#define IRODS_HTTP_API_CRLF_PARSER_HPP

#include "common.hpp"

#include <optional>
#include <string_view>

namespace irods::http
{
    class crlf_parser
    {
      public:
        explicit crlf_parser(const std::string_view _s)
            : data_{_s}
        {
        }

        auto next_crlf() -> bool
        {
            if (spos_ == 0 && epos_ == 0) {
                epos_ = data_.find("\r\n");
            }
            else if (epos_ != std::string_view::npos) {
                spos_ = std::clamp(epos_ + 2, epos_, std::string_view::npos); // Skip CRLF.
                epos_ = data_.find("\r\n", spos_);
            }

            return std::string_view::npos != epos_;
        }

        auto data() -> std::string_view
        {
            return data_.substr(spos_, epos_ - spos_);
        }

      private:
        const std::string_view data_;
        std::string_view::size_type spos_ = 0;
        std::string_view::size_type epos_ = 0;
    }; // class crlf_parser

    auto get_multipart_form_data_boundary(const std::string_view _data) -> std::optional<std::string_view>;

    auto parse_multipart_form_data(const std::string_view _boundary,
                                   const std::string_view _data) -> query_arguments_type;
} // namespace irods::http

#endif // IRODS_HTTP_API_CRLF_PARSER_HPP
