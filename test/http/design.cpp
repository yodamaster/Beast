//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <beast/unit_test/suite.hpp>

#include <beast/core/stream_concepts.hpp>
#include <beast/core/error.hpp>
#include <beast/core/flat_streambuf.hpp>
#include <beast/http/basic_parser.hpp>
#include <beast/http/concepts.hpp>
#include <beast/http/header_parser.hpp>
#include <beast/http/message_parser.hpp>
#include <beast/test/string_istream.hpp>
#include <beast/test/yield_to.hpp>

namespace beast {
namespace http {

/** Parse some HTTP/1 message data from a stream.
*/
template<
    class SyncReadStream,
    class DynamicBuffer,
    bool isRequest,
    class Fields>
void
parse_some(
    SyncReadStream& stream,
    DynamicBuffer& dynabuf,
    header_parser<isRequest, Fields>& parser,
    error_code& ec)
{
    static_assert(is_SyncReadStream<SyncReadStream>::value,
        "SyncReadStream requirements not met");
    static_assert(is_DynamicBuffer<DynamicBuffer>::value,
        "DynamicBuffer requirements not met");
    BOOST_ASSERT(parser.need_more());
    BOOST_ASSERT(! parser.is_done());
    auto used =
        parser.write(dynabuf.data(), ec);
    if(ec)
        return;
    dynabuf.consume(used);
    if(parser.need_more())
    {
        boost::optional<typename
            DynamicBuffer::mutable_buffers_type> mb;
        auto const size =
            read_size_helper(dynabuf, 65536);
        BOOST_ASSERT(size > 0);
        try
        {
            mb.emplace(dynabuf.prepare(size));
        }
        catch(std::length_error const&)
        {
            ec = error::buffer_overflow;
            return;
        }
        dynabuf.commit(stream.read_some(*mb, ec));
        if(ec == boost::asio::error::eof)
        {
            // Caller will see eof on next read.
            ec = {};
            parser.write_eof(ec);
            if(ec)
                return;
            BOOST_ASSERT(! parser.need_more());
        }
        else if(ec)
        {
            return;
        }
    }
}

template<
    class SyncReadStream,
    class DynamicBuffer,
    bool isRequest,
    class Fields>
void
parse(
    SyncReadStream& stream,
    DynamicBuffer& dynabuf,
    header_parser<isRequest, Fields>& parser,
    error_code& ec)
{
    do
    {
        parse_some(stream, dynabuf, parser, ec);
        if(ec)
            return;
    }
    while(! parser.is_done());
}

/** Parse some data from the stream.
*/
template<
    class SyncReadStream,
    class DynamicBuffer,
    bool isRequest,
    class Body,
    class Fields>
void
parse_some(
    SyncReadStream& stream,
    DynamicBuffer& dynabuf,
    message_parser<isRequest, Body, Fields>& parser,
    error_code& ec)
{
    static_assert(is_SyncReadStream<SyncReadStream>::value,
        "SyncReadStream requirements not met");
    static_assert(is_DynamicBuffer<DynamicBuffer>::value,
        "DynamicBuffer requirements not met");
    BOOST_ASSERT(! parser.is_done());
    // See if the parser needs more structured
    // data in order to make forward progress
    //
    if(parser.need_more())
    {
        // Give the parser what we have already
        //
        auto used =
            parser.write(dynabuf.data(), ec);
        if(ec)
            return;
        dynabuf.consume(used);
        if(parser.need_more())
        {
            // Parser needs even more, try to read it
            //
            boost::optional<typename
                DynamicBuffer::mutable_buffers_type> mb;
            auto const size =
                read_size_helper(dynabuf, 65536); // magic number?
            BOOST_ASSERT(size > 0);
            try
            {
                mb.emplace(dynabuf.prepare(size));
            }
            catch(std::length_error const&)
            {
                // Convert the exception to an error
                ec = error::buffer_overflow;
                return;
            }
            auto const bytes_transferred =
                stream.read_some(*mb, ec);
            if(ec == boost::asio::error::eof)
            {
                BOOST_ASSERT(bytes_transferred == 0);
                // Caller will see eof on next read.
                ec = {};
                parser.write_eof(ec);
                if(ec)
                    return;
                BOOST_ASSERT(! parser.need_more());
                BOOST_ASSERT(parser.is_done());
            }
            else if(! ec)
            {
                dynabuf.commit(bytes_transferred);
            }
            else
            {
                return;
            }
        }
    }
    else if(! parser.is_done())
    {
        // Apply any remaining bytes in dynabuf
        //
        parser.consume(dynabuf, ec);
        if(ec)
            return;

        // Parser wants a direct read
        //
        auto const mb = parser.prepare(
            dynabuf, 65536); // magic number?
        auto const bytes_transferred =
            stream.read_some(mb, ec);
        if(ec == boost::asio::error::eof)
        {
            BOOST_ASSERT(bytes_transferred == 0);
            // Caller will see eof on next read.
            ec = {};
            parser.write_eof(ec);
            if(ec)
                return;
            BOOST_ASSERT(! parser.need_more());
            BOOST_ASSERT(parser.is_done());
        }
        else if(! ec)
        {
            parser.commit(bytes_transferred);
        }
        else
        {
            return;
        }
    }
}

class design_test
    : public beast::unit_test::suite
    , public beast::test::enable_yield_to
{
public:
    void
    run() override
    {
        auto const s =
            "GET / HTTP/1.1\r\n"
            "User-Agent: Beast\r\n"
            "\r\n";
        beast::test::string_istream ss{get_io_service(), s};
        error_code ec;
        header_parser<true, fields> p;
        flat_streambuf buf;
        buf.reserve(1024);
        parse(ss, buf, p, ec);
        pass();
    }
};

BEAST_DEFINE_TESTSUITE(design,http,beast);

} // http
} // beast
