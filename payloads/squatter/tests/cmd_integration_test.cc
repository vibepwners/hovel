// Regression test for the cmd module. The module runs cmd.exe /c with the
// operator-provided command, streams combined stdout/stderr, then reports the
// process exit code before closing the mux stream.
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

    peer.SendOpen(1, "cmd", {"echo", "squatter-cmd-ok"});

    RxFrame f = peer.Recv();
    ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    ASSERT_NE(f.payload.find("squatter-cmd-ok"), std::string::npos);

    f = peer.Recv();
    ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    EXPECT_EQ(f.payload, "exit=0");

    f = peer.Recv();
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

    bool saw_banner = false;
    bool saw_echo = false;
    for (int i = 0; i < 4 && !saw_banner; i++) {
        RxFrame f = peer.Recv();
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
        if (f.payload.find("Microsoft") != std::string::npos ||
            f.payload.find(">") != std::string::npos ||
            f.payload.find("interactive cmd.exe started") != std::string::npos) {
            saw_banner = true;
        }
    }
    EXPECT_TRUE(saw_banner);

    peer.SendFrame(SQ_FRAME_DATA, 2, "echo squatter-interactive-ok\r\n");
    for (int i = 0; i < 4 && !saw_echo; i++) {
        RxFrame f = peer.Recv();
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
        if (f.payload.find("squatter-interactive-ok") != std::string::npos) {
            saw_echo = true;
        }
    }
    EXPECT_TRUE(saw_echo);

    peer.SendFrame(SQ_FRAME_DATA, 2, "exit\r\n");

    for (;;) {
        RxFrame f = peer.Recv();
        if (f.kind == SQ_FRAME_CLOSE) {
            EXPECT_EQ(f.stream_id, 2u);
            break;
        }
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    }

    sq_session_destroy(sess);
}

}  // namespace
