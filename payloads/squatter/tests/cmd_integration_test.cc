// Regression test for the cmd module. The module runs cmd.exe /c with the
// operator-provided command, streams combined stdout/stderr as DATA, then
// reports process state out of band before closing the mux stream.
#include <gtest/gtest.h>

#include <string>

#include "mux_peer.h"

#include "runtime/channel.h"
#include "modules/cmd.h"
#include "runtime/module.h"
#include "runtime/session.h"

namespace {

using muxtest::Peer;
using muxtest::RxFrame;

const sq_module kModules[] = {{"cmd", sq_cmd_module_main}};
const sq_module_table kTable = {kModules, 1};

class CmdIntegration : public muxtest::WsaFixture {};

TEST_F(CmdIntegration, RunsCommandAndReportsExitCode) {
    SOCKET client = INVALID_SOCKET, server = INVALID_SOCKET;
    ASSERT_TRUE(muxtest::LoopbackPair(&client, &server));
    sq_session* sess = sq_session_create(sq_channel_from_socket(server), &kTable);
    ASSERT_NE(sess, nullptr);
    Peer peer(client);

    peer.SendOpen(1, "cmd", {"echo squatter-cmd-ok"});

    bool saw_output = false;
    bool saw_exit = false;
    for (int i = 0; i < 32 && !saw_exit; ++i) {
        RxFrame f = peer.Recv();
        ASSERT_EQ(f.stream_id, 1u);
        if (f.kind == SQ_FRAME_DATA) {
            if (f.payload.find("squatter-cmd-ok") != std::string::npos) {
                saw_output = true;
            }
            continue;
        }
        ASSERT_EQ(f.kind, SQ_FRAME_CONTROL);
        sqmux_StreamEvent event{};
        ASSERT_TRUE(muxtest::DecodeEvent(f, &event));
        EXPECT_EQ(event.kind, SQMUX_EVENT_EXITED);
        saw_exit = true;
    }
    EXPECT_TRUE(saw_output);
    EXPECT_TRUE(saw_exit);

    RxFrame f = muxtest::RecvUntilKind(&peer, 1, SQ_FRAME_CLOSE);
    EXPECT_EQ(f.kind, SQ_FRAME_CLOSE);
    EXPECT_EQ(f.stream_id, 1u);

    sq_session_destroy(sess);
}

TEST_F(CmdIntegration, OpensInteractiveCommandShell) {
    SOCKET client = INVALID_SOCKET, server = INVALID_SOCKET;
    ASSERT_TRUE(muxtest::LoopbackPair(&client, &server));
    sq_session* sess = sq_session_create(sq_channel_from_socket(server), &kTable);
    ASSERT_NE(sess, nullptr);
    Peer peer(client);

    peer.SendOpen(2, "cmd", {});

    bool saw_interactive = false;
    bool saw_echo = false;
    for (int i = 0; i < 8 && !saw_interactive; i++) {
        RxFrame f = peer.Recv();
        if (f.kind == SQ_FRAME_CONTROL) {
            sqmux_StreamEvent event{};
            ASSERT_TRUE(muxtest::DecodeEvent(f, &event));
            EXPECT_EQ(event.kind, SQMUX_EVENT_INTERACTIVE);
            saw_interactive = true;
            break;
        }
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    }
    EXPECT_TRUE(saw_interactive);

    peer.SendFrame(SQ_FRAME_DATA, 2, "echo squatter-interactive-ok\r\n");
    for (int i = 0; i < 16 && !saw_echo; i++) {
        RxFrame f = peer.Recv();
        ASSERT_EQ(f.stream_id, 2u);
        if (f.kind == SQ_FRAME_CONTROL) {
            continue;
        }
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
        if (f.payload.find("squatter-interactive-ok") != std::string::npos) {
            saw_echo = true;
        }
    }
    EXPECT_TRUE(saw_echo);

    peer.SendFrame(SQ_FRAME_DATA, 2, "exit\r\n");

    bool saw_close = false;
    for (int i = 0; i < 32; ++i) {
        RxFrame f = peer.Recv();
        ASSERT_EQ(f.stream_id, 2u);
        if (f.kind == SQ_FRAME_CLOSE) {
            EXPECT_EQ(f.stream_id, 2u);
            saw_close = true;
            break;
        }
        ASSERT_TRUE(f.kind == SQ_FRAME_DATA || f.kind == SQ_FRAME_CONTROL);
    }
    EXPECT_TRUE(saw_close);

    sq_session_destroy(sess);
}

}  // namespace
