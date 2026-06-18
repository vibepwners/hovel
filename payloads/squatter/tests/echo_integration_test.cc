// End-to-end proof of the multiplexed stream/module runtime, exercised by the
// echo module:
//   * a real TCP loopback connection carries the framed protocol
//   * the server side runs an sq_session that dispatches OPEN to the echo module
//   * the echo module echoes its argc/argv, then echoes data, then closes on END
//
// If this passes under wine, every layer works together: transport -> framing
// -> mux/demux -> stream -> message-mode pipe -> module -> graceful close.
#include <gtest/gtest.h>

#include <map>
#include <string>
#include <vector>

#include "mux_peer.h"

#include "runtime/channel.h"
#include "modules/echo.h"
#include "runtime/module.h"
#include "runtime/session.h"

namespace {

using muxtest::LoopbackPair;
using muxtest::Peer;
using muxtest::RxFrame;

const sq_module kModules[] = {{"echo", sq_echo_module_main}};
const sq_module_table kTable = {kModules, 1};

using EchoIntegration = muxtest::WsaFixture;

TEST_F(EchoIntegration, EchoesArgvThenDataThenClosesOnEnd) {
    SOCKET client = INVALID_SOCKET, server = INVALID_SOCKET;
    ASSERT_TRUE(LoopbackPair(&client, &server));

    // Server side: a session that knows the echo module owns the server socket.
    sq_channel* ch = sq_channel_from_socket(server);
    ASSERT_NE(ch, nullptr);
    sq_session* sess = sq_session_create(ch, &kTable);
    ASSERT_NE(sess, nullptr);

    Peer peer(client);

    // 1. Open stream 1 running "echo" with three args.
    peer.SendOpen(1, "echo", {"alpha", "beta", "gamma"});

    // The module echoes argc/argv and also advertises stream interactivity.
    // Those frames can race through different session threads, so wait for the
    // data frame rather than depending on the CONTROL/DATA ordering.
    RxFrame f = muxtest::RecvUntilKind(&peer, 1, SQ_FRAME_DATA);
    EXPECT_EQ(f.kind, SQ_FRAME_DATA);
    EXPECT_EQ(f.stream_id, 1u);
    EXPECT_EQ(f.payload, "argc=4 echo alpha beta gamma");

    // 2. Send data; it must come back verbatim.
    peer.SendFrame(SQ_FRAME_DATA, 1, "hello world");
    f = muxtest::RecvUntilKind(&peer, 1, SQ_FRAME_DATA);
    EXPECT_EQ(f.kind, SQ_FRAME_DATA);
    EXPECT_EQ(f.stream_id, 1u);
    EXPECT_EQ(f.payload, "hello world");

    peer.SendFrame(SQ_FRAME_DATA, 1, "second message");
    f = muxtest::RecvUntilKind(&peer, 1, SQ_FRAME_DATA);
    EXPECT_EQ(f.payload, "second message");

    // 3. "END" makes the module close gracefully -> a CLOSE frame comes back.
    peer.SendFrame(SQ_FRAME_DATA, 1, "END");
    f = muxtest::RecvUntilKind(&peer, 1, SQ_FRAME_CLOSE);
    EXPECT_EQ(f.kind, SQ_FRAME_CLOSE);
    EXPECT_EQ(f.stream_id, 1u);

    sq_session_destroy(sess);  // closes the server socket too
}

// The headline feature: many independent streams (tasks) over ONE connection,
// interleaved, each echoing only its own data on its own stream id.
TEST_F(EchoIntegration, ManyStreamsMultiplexedOverOneConnection) {
    SOCKET client = INVALID_SOCKET, server = INVALID_SOCKET;
    ASSERT_TRUE(LoopbackPair(&client, &server));
    sq_channel* ch = sq_channel_from_socket(server);
    sq_session* sess = sq_session_create(ch, &kTable);
    ASSERT_NE(sess, nullptr);
    Peer peer(client);

    const int kStreams = 5;

    // Open all streams up front (ids 10..14), each with a distinct arg.
    for (int i = 0; i < kStreams; ++i) {
        std::string tag = "s" + std::to_string(i);
        peer.SendOpen(static_cast<UINT64>(10 + i), "echo", {tag.c_str()});
    }

    // Collect the argv echoes, bucketed by stream id (they may interleave).
    std::map<UINT64, std::vector<std::string>> got;
    for (int i = 0; i < kStreams * 4 && static_cast<int>(got.size()) < kStreams;
         ++i) {
        RxFrame f = peer.Recv();
        if (f.kind == SQ_FRAME_CONTROL) {
            continue;
        }
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
        got[f.stream_id].push_back(f.payload);
    }
    for (int i = 0; i < kStreams; ++i) {
        UINT64 sid = static_cast<UINT64>(10 + i);
        ASSERT_EQ(got[sid].size(), 1u);
        EXPECT_EQ(got[sid][0], "argc=2 echo s" + std::to_string(i));
    }

    // Interleave data across all streams, then verify each came back on its own
    // stream id with its own payload -- no splicing between streams.
    for (int i = 0; i < kStreams; ++i) {
        peer.SendFrame(SQ_FRAME_DATA, static_cast<UINT64>(10 + i),
                       "payload-" + std::to_string(i));
    }
    std::map<UINT64, std::string> echoed;
    for (int i = 0; i < kStreams * 4 &&
                    static_cast<int>(echoed.size()) < kStreams;
         ++i) {
        RxFrame f = peer.Recv();
        if (f.kind == SQ_FRAME_CONTROL) {
            continue;
        }
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
        echoed[f.stream_id] = f.payload;
    }
    for (int i = 0; i < kStreams; ++i) {
        EXPECT_EQ(echoed[static_cast<UINT64>(10 + i)],
                  "payload-" + std::to_string(i));
    }

    // Close them all.
    for (int i = 0; i < kStreams; ++i) {
        peer.SendFrame(SQ_FRAME_DATA, static_cast<UINT64>(10 + i), "END");
    }
    std::map<UINT64, bool> closed;
    for (int i = 0; i < kStreams * 4 &&
                    static_cast<int>(closed.size()) < kStreams;
         ++i) {
        RxFrame f = peer.Recv();
        if (f.kind == SQ_FRAME_CONTROL) {
            continue;
        }
        EXPECT_EQ(f.kind, SQ_FRAME_CLOSE);
        closed[f.stream_id] = true;
    }
    for (int i = 0; i < kStreams; ++i) {
        EXPECT_TRUE(closed[static_cast<UINT64>(10 + i)]);
    }

    sq_session_destroy(sess);
}

TEST_F(EchoIntegration, UnknownModuleIsRejectedWithClose) {
    SOCKET client = INVALID_SOCKET, server = INVALID_SOCKET;
    ASSERT_TRUE(LoopbackPair(&client, &server));
    sq_channel* ch = sq_channel_from_socket(server);
    sq_session* sess = sq_session_create(ch, &kTable);
    ASSERT_NE(sess, nullptr);

    Peer peer(client);
    peer.SendOpen(7, "does-not-exist", {});
    RxFrame f = peer.Recv();
    ASSERT_EQ(f.kind, SQ_FRAME_CONTROL);
    EXPECT_EQ(f.stream_id, 7u);
    sqmux_StreamEvent event{};
    ASSERT_TRUE(muxtest::DecodeEvent(f, &event));
    EXPECT_EQ(event.kind, SQMUX_EVENT_ERROR);

    f = peer.Recv();
    EXPECT_EQ(f.kind, SQ_FRAME_CLOSE);
    EXPECT_EQ(f.stream_id, 7u);

    sq_session_destroy(sess);
}

}  // namespace
