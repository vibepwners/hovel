// Shared test helpers: a TCP loopback pair and a "peer" that speaks the mux
// wire protocol (send/receive whole frames), for the integration tests.
#ifndef SQ_TESTS_MUX_PEER_H
#define SQ_TESTS_MUX_PEER_H

#include <gtest/gtest.h>

#include <deque>
#include <string>
#include <vector>

#include "base/win.h"

#include "wire/control_codec.h"
#include "wire/frame.h"
#include "wire/framing.h"

namespace muxtest {

struct RxFrame {
    UINT16 kind;
    UINT64 stream_id;
    std::string payload;
};

inline int rx_sink(void* ctx, UINT16 kind, UINT64 stream_id, const BYTE* payload,
                   UINT32 length) {
    auto* q = static_cast<std::deque<RxFrame>*>(ctx);
    RxFrame f;
    f.kind = kind;
    f.stream_id = stream_id;
    if (length > 0) {
        f.payload.assign(reinterpret_cast<const char*>(payload), length);
    }
    q->push_back(std::move(f));
    return 0;
}

inline bool LoopbackPair(SOCKET* client, SOCKET* server) {
    SOCKET lst = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lst == INVALID_SOCKET) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lst, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
        return false;
    if (listen(lst, 1) != 0) return false;
    int alen = sizeof addr;
    if (getsockname(lst, reinterpret_cast<sockaddr*>(&addr), &alen) != 0)
        return false;

    SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET) return false;
    if (connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
        return false;
    SOCKET sv = accept(lst, nullptr, nullptr);
    closesocket(lst);
    *client = c;
    *server = sv;
    return c != INVALID_SOCKET && sv != INVALID_SOCKET;
}

inline bool DecodeEvent(const RxFrame& frame, sqmux_StreamEvent* out) {
    if (frame.kind != SQ_FRAME_CONTROL) {
        return false;
    }
    return sq_control_decode_event(
               reinterpret_cast<const BYTE*>(frame.payload.data()),
               static_cast<UINT32>(frame.payload.size()), out) != FALSE;
}

// One end of a connection: send frames, and receive whole frames (reassembled).
class Peer {
   public:
    explicit Peer(SOCKET s) : sock_(s), reader_(sq_frame_reader_new()) {}
    ~Peer() {
        sq_frame_reader_free(reader_);
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
    }

    void SendFrame(UINT16 kind, UINT64 sid, const std::string& body) {
        BYTE* buf = nullptr;
        UINT32 n = 0;
        ASSERT_TRUE(sq_frame_encode(kind, sid,
                                    reinterpret_cast<const BYTE*>(body.data()),
                                    static_cast<UINT32>(body.size()), &buf, &n));
        int off = 0;
        while (off < static_cast<int>(n)) {
            int w = send(sock_, reinterpret_cast<char*>(buf) + off,
                         static_cast<int>(n) - off, 0);
            ASSERT_GT(w, 0);
            off += w;
        }
        sq_frame_buffer_free(buf);
    }

    void SendOpen(UINT64 sid, const char* module,
                  const std::vector<const char*>& args) {
        BYTE* body = nullptr;
        UINT32 blen = 0;
        ASSERT_TRUE(sq_control_encode_open(module, args.data(),
                                           static_cast<int>(args.size()), &body,
                                           &blen));
        std::string b(reinterpret_cast<char*>(body), blen);
        sq_control_buffer_free(body);
        SendFrame(SQ_FRAME_OPEN, sid, b);
    }

    RxFrame Recv() {
        while (queue_.empty()) {
            BYTE buf[8192];
            int n = recv(sock_, reinterpret_cast<char*>(buf), sizeof buf, 0);
            EXPECT_GT(n, 0) << "connection closed before expected frame";
            if (n <= 0) return RxFrame{0, 0, "<eof>"};
            int rc = sq_frame_reader_push(reader_, buf, static_cast<UINT32>(n),
                                          rx_sink, &queue_);
            EXPECT_EQ(rc, 0);
        }
        RxFrame f = queue_.front();
        queue_.pop_front();
        return f;
    }

   private:
    SOCKET sock_;
    sq_frame_reader* reader_;
    std::deque<RxFrame> queue_;
};

inline RxFrame RecvUntilKind(Peer* peer, UINT64 stream_id, UINT16 kind,
                             int max_frames = 32) {
    for (int i = 0; i < max_frames; ++i) {
        RxFrame f = peer->Recv();
        EXPECT_EQ(f.stream_id, stream_id);
        if (f.kind == kind) {
            return f;
        }
    }
    ADD_FAILURE() << "expected frame kind " << kind << " for stream "
                  << stream_id;
    return RxFrame{0, stream_id, ""};
}

// Test fixture that brings Winsock up and down.
class WsaFixture : public ::testing::Test {
   protected:
    void SetUp() override {
        WSADATA w;
        ASSERT_EQ(WSAStartup(MAKEWORD(2, 2), &w), 0);
    }
    void TearDown() override { WSACleanup(); }
};

}  // namespace muxtest

#endif  // SQ_TESTS_MUX_PEER_H
