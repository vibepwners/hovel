#include <gtest/gtest.h>

#include "wire/frame.h"

namespace {

TEST(Frame, HeaderRoundtrip) {
    sq_frame_header in = {};
    in.length = 12345;
    in.kind = SQ_FRAME_DATA;
    in.flags = 0;
    in.stream_id = 0x1122334455667788ull;

    BYTE buf[SQ_FRAME_HEADER_SIZE] = {};
    sq_frame_header_encode(&in, buf);

    sq_frame_header out = {};
    ASSERT_TRUE(sq_frame_header_decode(buf, &out));
    EXPECT_EQ(out.length, in.length);
    EXPECT_EQ(out.kind, in.kind);
    EXPECT_EQ(out.flags, in.flags);
    EXPECT_EQ(out.stream_id, in.stream_id);
}

TEST(Frame, IsLittleEndian) {
    sq_frame_header in = {};
    in.length = 0x04030201u;
    in.stream_id = 0x0807060504030201ull;
    BYTE buf[SQ_FRAME_HEADER_SIZE] = {};
    sq_frame_header_encode(&in, buf);

    EXPECT_EQ(buf[0], 0x01);  // length LSB first
    EXPECT_EQ(buf[3], 0x04);
    EXPECT_EQ(buf[8], 0x01);  // stream_id at offset 8, LSB first
    EXPECT_EQ(buf[15], 0x08);
}

TEST(Frame, RejectsOversizeLength) {
    BYTE buf[SQ_FRAME_HEADER_SIZE] = {};
    for (int i = 0; i < 4; ++i) buf[i] = 0xFF;  // length = 0xFFFFFFFF
    sq_frame_header out = {};
    EXPECT_FALSE(sq_frame_header_decode(buf, &out));
    EXPECT_EQ(out.length, 0u);  // left zeroed on failure
}

TEST(Frame, RejectsUnknownKind) {
    sq_frame_header in = {};
    in.length = 8;
    in.kind = 99;  // not a valid kind
    BYTE buf[SQ_FRAME_HEADER_SIZE] = {};
    sq_frame_header_encode(&in, buf);
    sq_frame_header out = {};
    EXPECT_FALSE(sq_frame_header_decode(buf, &out));
}

TEST(Frame, AcceptsAllKnownKinds) {
    const sq_frame_kind kinds[] = {SQ_FRAME_DATA, SQ_FRAME_OPEN, SQ_FRAME_CLOSE};
    for (sq_frame_kind k : kinds) {
        sq_frame_header in = {};
        in.kind = static_cast<UINT16>(k);
        in.length = 0;
        BYTE buf[SQ_FRAME_HEADER_SIZE] = {};
        sq_frame_header_encode(&in, buf);
        sq_frame_header out = {};
        EXPECT_TRUE(sq_frame_header_decode(buf, &out)) << "kind=" << k;
        EXPECT_EQ(out.kind, static_cast<UINT16>(k));
    }
}

TEST(Frame, AcceptsMaxPayload) {
    sq_frame_header in = {};
    in.length = SQ_FRAME_MAX_PAYLOAD;
    in.kind = SQ_FRAME_DATA;
    BYTE buf[SQ_FRAME_HEADER_SIZE] = {};
    sq_frame_header_encode(&in, buf);
    sq_frame_header out = {};
    EXPECT_TRUE(sq_frame_header_decode(buf, &out));
    EXPECT_EQ(out.length, static_cast<UINT32>(SQ_FRAME_MAX_PAYLOAD));
}

}  // namespace
