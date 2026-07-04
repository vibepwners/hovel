#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "wire/framing.h"

namespace {

struct Frame {
    UINT16 kind;
    UINT64 stream_id;
    std::string payload;
};

// Sink that records every complete frame the reader surfaces.
int collect(void* ctx, UINT16 kind, UINT64 stream_id, const BYTE* payload,
            UINT32 length) {
    auto* out = static_cast<std::vector<Frame>*>(ctx);
    Frame f;
    f.kind = kind;
    f.stream_id = stream_id;
    f.payload.assign(reinterpret_cast<const char*>(payload),
                     reinterpret_cast<const char*>(payload) + length);
    out->push_back(std::move(f));
    return 0;
}

// Encode a frame into a std::string for convenient concatenation/splitting.
std::string Encode(UINT16 kind, UINT64 sid, const std::string& body) {
    BYTE* buf = nullptr;
    UINT32 n = 0;
    EXPECT_TRUE(sq_frame_encode(
        kind, sid, reinterpret_cast<const BYTE*>(body.data()),
        static_cast<UINT32>(body.size()), &buf, &n));
    std::string out(reinterpret_cast<char*>(buf), n);
    sq_frame_buffer_free(buf);
    return out;
}

class Reader {
   public:
    Reader() : r_(sq_frame_reader_new()) {}
    ~Reader() { sq_frame_reader_free(r_); }
    int Push(const std::string& bytes) {
        return sq_frame_reader_push(
            r_, reinterpret_cast<const BYTE*>(bytes.data()),
            static_cast<UINT32>(bytes.size()), collect, &frames);
    }
    std::vector<Frame> frames;

   private:
    sq_frame_reader* r_;
};

TEST(Framing, WholeFrameRoundtrip) {
    Reader rd;
    ASSERT_EQ(rd.Push(Encode(SQ_FRAME_DATA, 7, "hello")), 0);
    ASSERT_EQ(rd.frames.size(), 1u);
    EXPECT_EQ(rd.frames[0].kind, SQ_FRAME_DATA);
    EXPECT_EQ(rd.frames[0].stream_id, 7u);
    EXPECT_EQ(rd.frames[0].payload, "hello");
}

// The whole point: no matter how the transport chops the byte stream, the
// reader surfaces each message exactly once and complete.
TEST(Framing, ByteByByteReassembly) {
    std::string wire = Encode(SQ_FRAME_DATA, 42, "a longer payload here");
    Reader rd;
    for (char c : wire) {
        ASSERT_EQ(rd.Push(std::string(1, c)), 0);
    }
    ASSERT_EQ(rd.frames.size(), 1u);
    EXPECT_EQ(rd.frames[0].stream_id, 42u);
    EXPECT_EQ(rd.frames[0].payload, "a longer payload here");
}

TEST(Framing, CoalescedFramesInOrder) {
    std::string wire = Encode(SQ_FRAME_OPEN, 1, "open") +
                       Encode(SQ_FRAME_DATA, 1, "data1") +
                       Encode(SQ_FRAME_DATA, 1, "data2") +
                       Encode(SQ_FRAME_CLOSE, 1, "");
    Reader rd;
    ASSERT_EQ(rd.Push(wire), 0);
    ASSERT_EQ(rd.frames.size(), 4u);
    EXPECT_EQ(rd.frames[0].kind, SQ_FRAME_OPEN);
    EXPECT_EQ(rd.frames[1].payload, "data1");
    EXPECT_EQ(rd.frames[2].payload, "data2");
    EXPECT_EQ(rd.frames[3].kind, SQ_FRAME_CLOSE);
    EXPECT_EQ(rd.frames[3].payload, "");
}

// Two streams interleaved at frame granularity stay perfectly separable -- a
// message from one stream is never spliced into another's.
TEST(Framing, InterleavedStreamsNotInterspliced) {
    std::string wire = Encode(SQ_FRAME_DATA, 100, "A-first") +
                       Encode(SQ_FRAME_DATA, 200, "B-first") +
                       Encode(SQ_FRAME_DATA, 100, "A-second") +
                       Encode(SQ_FRAME_DATA, 200, "B-second");
    // Push in awkward 3-byte chunks to stress the state machine.
    Reader rd;
    for (size_t i = 0; i < wire.size(); i += 3) {
        ASSERT_EQ(rd.Push(wire.substr(i, 3)), 0);
    }
    ASSERT_EQ(rd.frames.size(), 4u);
    EXPECT_EQ(rd.frames[0].stream_id, 100u);
    EXPECT_EQ(rd.frames[0].payload, "A-first");
    EXPECT_EQ(rd.frames[1].stream_id, 200u);
    EXPECT_EQ(rd.frames[1].payload, "B-first");
    EXPECT_EQ(rd.frames[2].stream_id, 100u);
    EXPECT_EQ(rd.frames[2].payload, "A-second");
    EXPECT_EQ(rd.frames[3].stream_id, 200u);
    EXPECT_EQ(rd.frames[3].payload, "B-second");
}

TEST(Framing, EmptyPayload) {
    Reader rd;
    ASSERT_EQ(rd.Push(Encode(SQ_FRAME_CLOSE, 9, "")), 0);
    ASSERT_EQ(rd.frames.size(), 1u);
    EXPECT_EQ(rd.frames[0].payload.size(), 0u);
    EXPECT_EQ(rd.frames[0].stream_id, 9u);
}

TEST(Framing, RejectsCorruptHeader) {
    // A header claiming an absurd length must be rejected, not trusted.
    std::string bad(SQ_FRAME_HEADER_SIZE, '\0');
    for (int i = 0; i < 4; ++i) bad[i] = '\xFF';  // length = 0xFFFFFFFF
    Reader rd;
    EXPECT_EQ(rd.Push(bad), -1);
    EXPECT_TRUE(rd.frames.empty());
}

TEST(Framing, BigPayloadRoundtrip) {
    std::string big(200000, 'x');
    Reader rd;
    std::string wire = Encode(SQ_FRAME_DATA, 5, big);
    // split into 4096-byte transport reads
    for (size_t i = 0; i < wire.size(); i += 4096) {
        ASSERT_EQ(rd.Push(wire.substr(i, 4096)), 0);
    }
    ASSERT_EQ(rd.frames.size(), 1u);
    EXPECT_EQ(rd.frames[0].payload.size(), big.size());
    EXPECT_EQ(rd.frames[0].payload, big);
}

}  // namespace
