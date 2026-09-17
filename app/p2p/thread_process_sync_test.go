package p2p

import (
	"bytes"
	"context"
	"io"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/config"
)

// scriptedStream is a network.Stream fake that serves bytes from a scripted reader,
// records what the thread writes back to the peer, and reports whether it was closed.
// Only the methods ProcessSyncMessage touches are implemented; every other
// network.Stream method is left to the embedded nil interface and panics if called.
type scriptedStream struct {
	network.Stream

	reader  io.Reader
	conn    network.Conn
	written bytes.Buffer

	mu     sync.Mutex
	closed bool
}

// Read serves the scripted peer bytes
func (s *scriptedStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

// Write records the bytes the thread sends to the peer
func (s *scriptedStream) Write(p []byte) (int, error) { return s.written.Write(p) }

// Conn returns the fake connection used for IsClosed checks
func (s *scriptedStream) Conn() network.Conn { return s.conn }

// ID returns a stable fake stream identifier used only for logging
func (s *scriptedStream) ID() string { return "scripted-stream" }

// Close records that the thread closed the stream. Like a real libp2p stream, closing it
// unblocks a pending read: if the scripted reader is an io.Closer (e.g. an io.Pipe), it is
// closed too so a goroutine blocked reading the body returns instead of hanging.
func (s *scriptedStream) Close() error {
	if c, ok := s.reader.(io.Closer); ok {
		_ = c.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// isClosed reports whether Close has been called (safe for concurrent use)
func (s *scriptedStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// fakeConn is a network.Conn fake that only answers IsClosed.
type fakeConn struct {
	network.Conn

	closed bool
}

// IsClosed reports whether the fake connection is closed
func (c *fakeConn) IsClosed() bool { return c.closed }

// panicReader is an io.Reader whose Read always panics, to exercise the recover guard.
type panicReader struct{}

// Read always panics to simulate a hostile or buggy stream
func (panicReader) Read([]byte) (int, error) { panic("boom: simulated stream read panic") }

// varint encodes n as a Bitcoin CompactSize prefix, matching util.VarInt.ReadFrom.
// n is already a uint64 so no lossy conversion happens here.
func varint(n uint64) []byte { return util.VarInt(n).Bytes() }

// frame builds a length-prefixed sync frame from a raw body using the same writer the
// production code uses, so the declared length always matches the body length.
func frame(body []byte) []byte {
	w := util.NewWriter()
	w.WriteIntBytes(body)
	return w.Buf
}

// syncFrame builds a length-prefixed frame around a serialized SyncMessage.
func syncFrame(msg *SyncMessage) []byte { return frame(msg.Serialize()) }

// TestReadSyncFrame exercises the pure frame reader: it must reject an oversized declared
// length before allocating, decode every varint size branch, and never panic.
func TestReadSyncFrame(t *testing.T) {
	t.Run("oversized declared lengths are rejected before allocating", func(t *testing.T) {
		cases := map[string][]byte{
			"uint64 max":  varint(math.MaxUint64),
			"maxInt64":    varint(uint64(math.MaxInt64)),
			"maxInt64 +1": varint(uint64(math.MaxInt64) + 1),
			"one over 64": varint(65),
			"fd range":    varint(300),   // 0xfd two-byte prefix
			"fe range":    varint(70000), // 0xfe four-byte prefix
		}
		for name, prefix := range cases {
			t.Run(name, func(t *testing.T) {
				b, err := readSyncFrame(bytes.NewReader(prefix), 64)
				require.ErrorIs(t, err, ErrSyncMessageTooLarge)
				require.Nil(t, b, "no buffer must be returned when the frame is rejected")
			})
		}
	})

	t.Run("a frame exactly at the cap is accepted", func(t *testing.T) {
		body := bytes.Repeat([]byte{0x7}, 64)
		b, err := readSyncFrame(bytes.NewReader(frame(body)), 64)
		require.NoError(t, err)
		require.Len(t, b, 64)
		require.Equal(t, body, b)
	})

	t.Run("a zero-length frame decodes to an empty buffer", func(t *testing.T) {
		b, err := readSyncFrame(bytes.NewReader(varint(0)), 64)
		require.NoError(t, err)
		require.Empty(t, b)
	})

	t.Run("all varint size branches decode within the cap", func(t *testing.T) {
		for _, n := range []int{1, 200, 300, 70000} {
			body := bytes.Repeat([]byte{0x9}, n)
			b, err := readSyncFrame(bytes.NewReader(frame(body)), 1<<20)
			require.NoError(t, err)
			require.Len(t, b, n)
		}
	})

	t.Run("a truncated length prefix returns a read error, not too-large", func(t *testing.T) {
		b, err := readSyncFrame(bytes.NewReader([]byte{0xff, 0x01, 0x02}), 64)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrSyncMessageTooLarge)
		require.Nil(t, b)
	})

	t.Run("a body shorter than the declared length returns a read error", func(t *testing.T) {
		// Declares 10 bytes but only supplies 3.
		in := append(varint(10), 0x1, 0x2, 0x3)
		b, err := readSyncFrame(bytes.NewReader(in), 64)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrSyncMessageTooLarge)
		require.Nil(t, b)
	})

	t.Run("a zero cap falls back to the default", func(t *testing.T) {
		b, err := readSyncFrame(bytes.NewReader(frame([]byte("hello"))), 0)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), b)
	})
}

// TestStreamThread_ProcessSyncMessage covers the hardened stream loop end to end: an
// unauthenticated peer can no longer drive an unbounded allocation or crash the process.
func TestStreamThread_ProcessSyncMessage(t *testing.T) {
	// oversizedFrames are the malicious length prefixes a hostile peer might send. Each
	// would previously reach make([]byte, vi) and either OOM or panic-kill the process.
	oversizedFrames := map[string][]byte{
		"uint64 max":  varint(math.MaxUint64),
		"maxInt64":    varint(uint64(math.MaxInt64)),
		"maxInt64 +1": varint(uint64(math.MaxInt64) + 1),
	}
	for name, prefix := range oversizedFrames {
		t.Run("oversized frame is rejected and the process survives: "+name, func(t *testing.T) {
			deps := loadTestDependencies(t)
			stream := &scriptedStream{reader: bytes.NewReader(prefix), conn: &fakeConn{}}
			thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

			err := thread.ProcessSyncMessage(context.Background())
			require.ErrorIs(t, err, ErrSyncMessageTooLarge)
			require.True(t, stream.isClosed(), "the offending stream must be closed")
		})
	}

	t.Run("a frame one byte over the configured cap is rejected", func(t *testing.T) {
		deps := loadTestDependencies(t)
		deps.P2P.MaxMessageSizeBytes = 64
		stream := &scriptedStream{reader: bytes.NewReader(varint(65)), conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		require.ErrorIs(t, thread.ProcessSyncMessage(context.Background()), ErrSyncMessageTooLarge)
		require.True(t, stream.isClosed())
	})

	t.Run("a truncated frame closes the stream without a panic", func(t *testing.T) {
		deps := loadTestDependencies(t)
		// Declares 10 bytes, supplies 3, then EOF.
		in := append(varint(10), 0x1, 0x2, 0x3)
		stream := &scriptedStream{reader: bytes.NewReader(in), conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		require.NoError(t, thread.ProcessSyncMessage(context.Background()))
		require.True(t, stream.isClosed())
	})

	t.Run("a zero-length frame ends the exchange cleanly", func(t *testing.T) {
		deps := loadTestDependencies(t)
		stream := &scriptedStream{reader: bytes.NewReader(varint(0)), conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		require.NoError(t, thread.ProcessSyncMessage(context.Background()))
		require.True(t, stream.isClosed())
	})

	t.Run("an unknown message type closes the stream gracefully", func(t *testing.T) {
		deps := loadTestDependencies(t)
		// A well-formed 5-byte frame whose type byte (0x00) is not a known sync type.
		unknown := frame([]byte{0x00, 0x01, 0x02, 0x03, 0x04})
		stream := &scriptedStream{reader: bytes.NewReader(unknown), conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		require.NoError(t, thread.ProcessSyncMessage(context.Background()))
		require.True(t, stream.isClosed())
	})

	t.Run("a body the peer never fills times out without hanging or crashing", func(t *testing.T) {
		deps := loadTestDependencies(t)
		deps.P2P.SyncTimeout = 100 * time.Millisecond

		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() })
		// Declare 10 body bytes but never deliver them.
		go func() { _, _ = pw.Write(varint(10)) }()

		stream := &scriptedStream{reader: pr, conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		start := time.Now()
		err := thread.ProcessSyncMessage(context.Background())
		require.ErrorIs(t, err, ErrSyncTimeout)
		require.Less(t, time.Since(start), 5*time.Second, "must return promptly on the configured timeout")
		require.True(t, stream.isClosed(), "the timeout must close the stream and terminate the exchange")
	})

	t.Run("a panic in the reader goroutine is recovered and does not kill the process", func(t *testing.T) {
		deps := loadTestDependencies(t)
		stream := &scriptedStream{reader: panicReader{}, conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		err := thread.ProcessSyncMessage(context.Background())
		require.ErrorIs(t, err, ErrSyncPanic)
		require.True(t, stream.isClosed())
	})

	t.Run("a valid IWantLatest frame is answered with the latest alert", func(t *testing.T) {
		deps := loadTestDependencies(t)
		in := syncFrame(&SyncMessage{Type: IWantLatest})
		stream := &scriptedStream{reader: bytes.NewReader(in), conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		// After answering, the scripted reader is exhausted (EOF), so the loop closes.
		require.NoError(t, thread.ProcessSyncMessage(context.Background()))
		require.True(t, stream.isClosed())

		reply := decodeFramedSyncMessage(t, stream.written.Bytes())
		require.Equal(t, byte(IGotLatest), reply.Type, "peer must be told our latest sequence")
	})

	t.Run("multiple frames on one stream are processed across loop iterations", func(t *testing.T) {
		deps := loadTestDependencies(t)
		// Two IWantLatest frames back to back, then EOF.
		in := append(syncFrame(&SyncMessage{Type: IWantLatest}), syncFrame(&SyncMessage{Type: IWantLatest})...)
		stream := &scriptedStream{reader: bytes.NewReader(in), conn: &fakeConn{}}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		require.NoError(t, thread.ProcessSyncMessage(context.Background()))
		require.True(t, stream.isClosed())
		require.GreaterOrEqual(t, stream.written.Len(), 2, "both requests should be answered")
	})
}

// TestStreamThread_ProcessSyncMessage_ConcurrentOversized proves that many hostile peers
// blasting oversized frames at once are all rejected and the process stays alive.
func TestStreamThread_ProcessSyncMessage_ConcurrentOversized(t *testing.T) {
	deps := loadTestDependencies(t)

	const peers = 32
	var wg sync.WaitGroup
	errs := make([]error, peers)
	for i := range peers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stream := &scriptedStream{reader: bytes.NewReader(varint(math.MaxUint64)), conn: &fakeConn{}}
			thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}
			errs[idx] = thread.ProcessSyncMessage(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.ErrorIs(t, err, ErrSyncMessageTooLarge, "peer %d must be rejected", i)
	}
}

// TestStreamThread_Sync_RejectsOversizedResponse proves the bound also protects the
// outbound dialer path: an oversized reply surfaces so discoverPeers skips the peer.
func TestStreamThread_Sync_RejectsOversizedResponse(t *testing.T) {
	deps := loadTestDependencies(t)
	stream := &scriptedStream{reader: bytes.NewReader(varint(math.MaxUint64)), conn: &fakeConn{}}
	thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

	require.ErrorIs(t, thread.Sync(context.Background()), ErrSyncMessageTooLarge)
}

// TestStreamThread_syncConfigHelpers verifies the config-backed limits fall back to safe
// defaults when the config is nil or unset, and honor a positive configured value.
func TestStreamThread_syncConfigHelpers(t *testing.T) {
	t.Run("max sync message bytes", func(t *testing.T) {
		require.Equal(t, uint64(config.DefaultP2PMaxMessageSizeBytes), (&StreamThread{}).maxSyncMessageBytes(),
			"a nil config must fall back to the default")

		zero := &StreamThread{config: &config.Config{}}
		require.Equal(t, uint64(config.DefaultP2PMaxMessageSizeBytes), zero.maxSyncMessageBytes(),
			"a zero value must fall back to the default")

		custom := &StreamThread{config: &config.Config{P2P: config.P2PConfig{MaxMessageSizeBytes: 4096}}}
		require.Equal(t, uint64(4096), custom.maxSyncMessageBytes())
	})

	t.Run("sync timeout", func(t *testing.T) {
		require.Equal(t, config.DefaultSyncTimeout, (&StreamThread{}).syncTimeout(),
			"a nil config must fall back to the default")

		zero := &StreamThread{config: &config.Config{}}
		require.Equal(t, config.DefaultSyncTimeout, zero.syncTimeout(),
			"a zero value must fall back to the default")

		custom := &StreamThread{config: &config.Config{P2P: config.P2PConfig{SyncTimeout: 3 * time.Second}}}
		require.Equal(t, 3*time.Second, custom.syncTimeout())
	})
}

// decodeFramedSyncMessage strips the varint length prefix and parses the sync message.
func decodeFramedSyncMessage(t *testing.T, framed []byte) *SyncMessage {
	t.Helper()
	r := bytes.NewReader(framed)
	var vi util.VarInt
	_, err := vi.ReadFrom(r)
	require.NoError(t, err)
	body := make([]byte, vi)
	_, err = io.ReadFull(r, body)
	require.NoError(t, err)
	msg, err := NewSyncMessageFromBytes(body)
	require.NoError(t, err)
	return msg
}
