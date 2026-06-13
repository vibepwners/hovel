#include <gtest/gtest.h>

#include "pb_encode.h"
#include "pb_decode.h"

#include "tests/test.pb.h"

TEST(Nanopb, ScalarRoundtrip) {
    uint8_t buf[64];
    Point out = Point_init_zero;
    out.x = 42;
    out.y = -7;
    out.flag = true;

    pb_ostream_t os = pb_ostream_from_buffer(buf, sizeof buf);
    ASSERT_TRUE(pb_encode(&os, Point_fields, &out));
    const size_t n = os.bytes_written;
    EXPECT_GT(n, 0u);

    Point in = Point_init_zero;
    pb_istream_t is = pb_istream_from_buffer(buf, n);
    ASSERT_TRUE(pb_decode(&is, Point_fields, &in));
    EXPECT_EQ(in.x, 42);
    EXPECT_EQ(in.y, -7);
    EXPECT_TRUE(in.flag);
}
