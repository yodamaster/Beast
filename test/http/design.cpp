//
// Copyright (c) 2013-2017 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <beast/unit_test/suite.hpp>

#include <beast/core/error.hpp>
#include <beast/http/basic_parser.hpp>

namespace beast {
namespace http {

/*

Parse states:

- need header
- at body
- at body-eof
- need chunk header
- at chunk



*/

#if 0
template<
    class SyncReadStream,
    class DynamicBuffer,
    class Parser>
void
new_parse(
    SyncReadStream& stream,
    DynamicBuffer& dynabuf,
    Parser& parser,
    error_code& ec)
{
    static_assert(is_SyncReadStream<SyncReadStream>::value,
        "SyncReadStream requirements not met");
    static_assert(is_DynamicBuffer<DynamicBuffer>::value,
        "DynamicBuffer requirements not met");
    static_assert(is_Parser<Parser>::value,
        "Parser requirements not met");
    for(;;)
    {
        auto used =
            parser.write(dynabuf.data(), ec);
        if(ec)
            return;
        dynabuf.consume(used);
        if(! parser.need_more())
            break;
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
            break;
        }
        if(ec)
            return;
    }
}

template<
    class SyncReadStream,
    class DynamicBuffer,
    bool isRequest,
    class Derived>
void
parse_body_direct(
    SyncReadStream& stream,
    DynamicBuffer& dynabuf,
    basic_parser<isRequest, Derived>& parser,
    error_code& ec)
{
    switch(parser.body_style())
    {
    case 0: // content-length
    {

        break;
    }

    case 1: // eof
    {
        break;
    }

    case 2: // chunked
    {
        break;
    }
    }
}
#endif

class design_test : public beast::unit_test::suite
{
public:
    void
    run() override
    {
    }
};

BEAST_DEFINE_TESTSUITE(design,http,beast);

} // http
} // beast
