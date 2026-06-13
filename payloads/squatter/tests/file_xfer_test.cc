// Regression test for the getfile/putfile modules and their D/E/S sub-protocol
// (see src/modules/file_xfer.h). Uses multi-chunk payloads to exercise the
// streaming path. The test process is both peer and server (in-process
// session), so a relative path names the same file on both sides.
#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>

#include "mux_peer.h"

#include "runtime/channel.h"
#include "modules/file_xfer.h"
#include "modules/getfile.h"
#include "runtime/module.h"
#include "modules/putfile.h"
#include "runtime/session.h"

namespace {

using muxtest::Peer;
using muxtest::RxFrame;

const sq_module kModules[] = {
    {"getfile", sq_getfile_module_main},
    {"putfile", sq_putfile_module_main},
};
const sq_module_table kTable = {kModules, 2};

std::string MakeBlob(size_t n, int seed) {
    std::string s;
    s.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(static_cast<char>((i * 31 + seed) & 0xFF));
    }
    return s;
}

class FileXfer : public muxtest::WsaFixture {};

TEST_F(FileXfer, GetfileStreamsWholeFile) {
    const char* path = "xfer_get_src.bin";
    const std::string content = MakeBlob(100000, 7);  // ~3 chunks
    {
        std::ofstream o(path, std::ios::binary);
        o.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    ASSERT_TRUE(muxtest::LoopbackPair(&c, &s));
    sq_session* sess = sq_session_create(sq_channel_from_socket(s), &kTable);
    ASSERT_NE(sess, nullptr);
    Peer peer(c);

    peer.SendOpen(1, "getfile", {path});

    RxFrame f = peer.Recv();  // STAT "OK <size>"
    ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    ASSERT_FALSE(f.payload.empty());
    ASSERT_EQ(static_cast<BYTE>(f.payload[0]), SQ_XFER_STAT);
    EXPECT_EQ(f.payload.substr(1), "OK " + std::to_string(content.size()));

    std::string got;
    bool eof = false;
    for (;;) {
        f = peer.Recv();
        if (f.kind == SQ_FRAME_CLOSE) break;
        ASSERT_EQ(f.kind, SQ_FRAME_DATA);
        ASSERT_FALSE(f.payload.empty());
        BYTE tag = static_cast<BYTE>(f.payload[0]);
        if (tag == SQ_XFER_DATA) {
            got += f.payload.substr(1);
        } else if (tag == SQ_XFER_EOF) {
            eof = true;
        }
    }
    EXPECT_TRUE(eof);
    EXPECT_EQ(got, content);

    sq_session_destroy(sess);
    DeleteFileA(path);
}

TEST_F(FileXfer, PutfileWritesWholeFile) {
    const char* path = "xfer_put_dst.bin";
    DeleteFileA(path);
    const std::string content = MakeBlob(70000, 19);  // ~3 chunks

    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    ASSERT_TRUE(muxtest::LoopbackPair(&c, &s));
    sq_session* sess = sq_session_create(sq_channel_from_socket(s), &kTable);
    ASSERT_NE(sess, nullptr);
    Peer peer(c);

    peer.SendOpen(1, "putfile", {path});

    RxFrame f = peer.Recv();  // STAT "OK" (ready)
    ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    ASSERT_FALSE(f.payload.empty());
    ASSERT_EQ(static_cast<BYTE>(f.payload[0]), SQ_XFER_STAT);
    ASSERT_EQ(f.payload.substr(1), "OK");

    for (size_t off = 0; off < content.size();) {
        size_t n = std::min<size_t>(SQ_XFER_CHUNK, content.size() - off);
        std::string msg(1, static_cast<char>(SQ_XFER_DATA));
        msg.append(content, off, n);
        peer.SendFrame(SQ_FRAME_DATA, 1, msg);
        off += n;
    }
    peer.SendFrame(SQ_FRAME_DATA, 1, std::string(1, static_cast<char>(SQ_XFER_EOF)));

    f = peer.Recv();  // STAT "OK <bytes>"
    ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    ASSERT_EQ(static_cast<BYTE>(f.payload[0]), SQ_XFER_STAT);
    EXPECT_EQ(f.payload.substr(1), "OK " + std::to_string(content.size()));

    f = peer.Recv();  // CLOSE
    EXPECT_EQ(f.kind, SQ_FRAME_CLOSE);

    sq_session_destroy(sess);

    std::ifstream in(path, std::ios::binary);
    std::string written((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
    EXPECT_EQ(written, content);
    DeleteFileA(path);
}

TEST_F(FileXfer, GetfileMissingFileReportsError) {
    SOCKET c = INVALID_SOCKET, s = INVALID_SOCKET;
    ASSERT_TRUE(muxtest::LoopbackPair(&c, &s));
    sq_session* sess = sq_session_create(sq_channel_from_socket(s), &kTable);
    ASSERT_NE(sess, nullptr);
    Peer peer(c);

    peer.SendOpen(1, "getfile", {"no_such_file_12345.bin"});
    RxFrame f = peer.Recv();
    ASSERT_EQ(f.kind, SQ_FRAME_DATA);
    ASSERT_EQ(static_cast<BYTE>(f.payload[0]), SQ_XFER_STAT);
    EXPECT_EQ(f.payload.substr(1, 3), "ERR");

    f = peer.Recv();
    EXPECT_EQ(f.kind, SQ_FRAME_CLOSE);
    sq_session_destroy(sess);
}

}  // namespace
