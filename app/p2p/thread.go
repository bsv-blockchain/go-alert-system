package p2p

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/bsv-blockchain/go-alert-system/app/config"
	"github.com/bsv-blockchain/go-alert-system/app/models"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
)

// Thread is an interface for a thread
type Thread interface {
	Start(ctx context.Context) error
	Kill(ctx context.Context) error
}

// StreamThread is a thread for a stream
type StreamThread struct {
	config           *config.Config
	ctx              context.Context //nolint:containedctx // TODO should remove this, should be passed in via methods only
	latestSequence   uint32
	myLatestSequence uint32
	peer             peer.ID
	stream           network.Stream
	quitChannel      chan bool
}

// LatestSequence will return the threads latest sequence
func (s *StreamThread) LatestSequence() uint32 {
	return s.latestSequence
}

// Sync will start the thread
func (s *StreamThread) Sync(ctx context.Context) error {
	// Get the latest alert
	a, err := models.GetLatestAlert(ctx, nil, model.WithAllDependencies(s.config))
	if err != nil {
		s.config.Services.Log.Errorf("failed to get latest alert: %s", err.Error())
		return err
	} else if a == nil {
		s.config.Services.Log.Error(ErrAlertNotLatest.Error())
		return ErrAlertNotLatest
	}

	s.myLatestSequence = a.SequenceNumber
	// construct get the latest message
	msg := SyncMessage{
		Type: IWantLatest,
	}
	data := msg.Serialize()

	defer func() {
		_ = s.stream.Close()
	}()

	writer := util.NewWriter()
	writer.WriteIntBytes(data)
	if _, err = s.stream.Write(writer.Buf); err != nil {
		return err
	}

	s.config.Services.Log.Debugf("requested latest sequence in stream %s", s.stream.ID())

	return s.ProcessSyncMessage(ctx)
}

// ProcessSyncMessage will process the sync message
func (s *StreamThread) ProcessSyncMessage(ctx context.Context) error {
	// Buffered so the reader goroutine's single send never blocks, even after the
	// outer select below has already returned via the timeout or quit channel. An
	// unbuffered channel here leaks the goroutine on those paths.
	done := make(chan error, 1)
	go func() {
		// Recover at the stream boundary so a single malformed peer stream (or any
		// unexpected panic) cannot terminate the whole host process.
		defer func() {
			if r := recover(); r != nil {
				s.config.Services.Log.Errorf("recovered from panic processing sync message from peer %s: %v", s.peer.String(), r)
				_ = s.stream.Close()
				// Non-blocking: the outer select may have already returned.
				select {
				case done <- fmt.Errorf("%w: peer %s", ErrSyncPanic, s.peer.String()):
				default:
				}
			}
		}()
		for {
			// readSyncFrame rejects an oversized declared length before allocating, so
			// an unauthenticated peer cannot drive an unbounded allocation or overflow
			// make and crash the process.
			b, err := readSyncFrame(s.stream, s.maxSyncMessageBytes())
			if err != nil {
				if s.stream.Conn().IsClosed() {
					done <- nil
					return
				}
				if errors.Is(err, ErrSyncMessageTooLarge) {
					s.config.Services.Log.Debugf("rejecting sync frame from peer %s: %s; closing stream", s.peer.String(), err.Error())
					_ = s.stream.Close()
					done <- err
					return
				}
				s.config.Services.Log.Debugf("failed to read sync message: %s; closing stream", err.Error())
				done <- s.stream.Close()
				return
			}

			if len(b) == 0 {
				_ = s.stream.Close()
				done <- nil
				return
			}
			var msg *SyncMessage
			if msg, err = NewSyncMessageFromBytes(b); err != nil {
				s.config.Services.Log.Errorf("failed to convert to sync message: %s", err.Error())
				done <- err
				return
			}
			switch msg.Type {
			case IGotLatest:
				s.config.Services.Log.Debugf("received latest sequence %d from peer %s", msg.SequenceNumber, s.peer.String())
				if err = s.ProcessGotLatest(ctx, msg); err != nil {
					done <- err
					return
				}
				if s.myLatestSequence >= s.latestSequence {
					_ = s.stream.Close()
					done <- nil
					return
				}
				s.config.Services.Log.Debugf("wrote msg requesting next sequence %d from peer %s", s.myLatestSequence+1, s.peer.String())
			case IGotSequenceNumber:
				s.config.Services.Log.Debugf("received IGotSequenceNumber %d from peer %s", msg.SequenceNumber, s.peer.String())
				if err = s.ProcessGotSequenceNumber(msg); err != nil {
					done <- err
					return
				}
				if s.myLatestSequence == s.latestSequence {
					_ = s.stream.Close()
					done <- nil
					return
				}
				s.config.Services.Log.Debugf("wrote msg requesting next sequence %d from peer %s", msg.SequenceNumber+1, s.peer.String())
			case IWantSequenceNumber:
				s.config.Services.Log.Debugf("received IWantSequenceNumber %d from peer %s", msg.SequenceNumber, s.peer.String())
				if err = s.ProcessWantSequenceNumber(ctx, msg); err != nil {
					done <- err
					return
				}
				s.config.Services.Log.Debugf("wrote sequence %d to peer %s", msg.SequenceNumber, s.peer.String())
				if msg.SequenceNumber == s.myLatestSequence {
					err = s.stream.Close()
					done <- err
					return
				}
			case IWantLatest:
				s.config.Services.Log.Debugf("received IWantLatest from peer %s", s.peer.String())
				if err = s.ProcessWantLatest(ctx); err != nil {
					done <- err
					return
				}
				s.config.Services.Log.Debugf("wrote latest sequence %d to peer %s", s.myLatestSequence, s.peer.String())
			default:
				// Every sync message type is known to this protocol, so an unknown type
				// signals a bad or incompatible peer. End the exchange gracefully rather
				// than loop until the timeout holding a goroutine and stream open.
				s.config.Services.Log.Debugf("received unknown sync message type %d from peer %s; closing stream", msg.Type, s.peer.String())
				_ = s.stream.Close()
				done <- nil
				return
			}
		}
	}()
	select {
	case <-s.quitChannel:
		s.config.Services.Log.Infof("quitting sync process")
		return nil
	case err := <-done:
		return err
	case <-time.After(s.syncTimeout()):
		// Close the stream so the timeout itself terminates the exchange: it unblocks the
		// reader goroutine's pending read (which then exits via the buffered done channel)
		// rather than relying on the caller to close afterward. ProcessSyncMessage is
		// exported, so a direct caller must not be left with a leaked goroutine or an open
		// stream. Close is idempotent, so the caller closing again is harmless.
		_ = s.stream.Close()
		return fmt.Errorf("%w: peer %s", ErrSyncTimeout, s.peer.String())
	}
}

// ProcessGotLatest will process the got latest message
func (s *StreamThread) ProcessGotLatest(ctx context.Context, msg *SyncMessage) error {
	a, err := models.GetLatestAlert(ctx, nil, model.WithAllDependencies(s.config))
	if err != nil {
		s.config.Services.Log.Errorf("failed to get latest alert to send to peer: %s", err.Error())
		return err
	} else if a == nil {
		s.config.Services.Log.Error(ErrAlertNotLatest.Error())
		return ErrAlertNotLatest
	}

	s.myLatestSequence = a.SequenceNumber // this is redundant, but doesn't hurt
	if msg.SequenceNumber < a.SequenceNumber {
		s.config.Services.Log.Debugf("peer %s is not synced yet, ignoring...", s.peer.String())
		return nil
	}

	s.latestSequence = msg.SequenceNumber
	if msg.SequenceNumber == a.SequenceNumber {
		s.config.Services.Log.Debugf("peer %s is synced to current state as us, closing stream.", s.peer.String())
		_ = s.stream.Close()
		return nil
	}
	s.config.Services.Log.Infof("peer %s has sequence %d and we have %d", s.peer.String(), msg.SequenceNumber, a.SequenceNumber)

	// need to get the next sequence
	res := SyncMessage{
		Type:           IWantSequenceNumber,
		SequenceNumber: a.SequenceNumber + 1,
	}
	writer := util.NewWriter()
	writer.WriteIntBytes(res.Serialize())
	_, err = s.stream.Write(writer.Buf)
	return err
}

// ProcessGotSequenceNumber will process the got sequence number message
func (s *StreamThread) ProcessGotSequenceNumber(msg *SyncMessage) error {
	// Sync with a new alert
	a, err := models.NewAlertFromBytes(msg.Data, model.WithAllDependencies(s.config), model.New())
	if err != nil {
		// todo probably want to ban this peer?
		return err
	}

	// Only accept the alert that directly follows what is stored, otherwise a peer
	// could replay an old (validly signed) alert such as a superseded set keys alert.
	// The stored latest is authoritative: a thread created by the inbound stream
	// handler never learns the local sequence (it starts at zero), and pubsub may
	// have delivered alerts while this sync was in flight.
	var latest *models.AlertMessage
	if latest, err = models.GetLatestAlert(s.ctx, nil, model.WithAllDependencies(s.config)); err != nil {
		return err
	}
	s.myLatestSequence = latest.SequenceNumber
	if a.SequenceNumber != s.myLatestSequence+1 {
		return fmt.Errorf(
			"%w: expected %d, got %d from peer %s",
			ErrUnexpectedSequenceNumber, s.myLatestSequence+1, a.SequenceNumber, s.peer.String(),
		)
	}

	// Verify signatures
	var valid bool
	if valid, err = a.AreSignaturesValid(s.ctx); err != nil {
		return err
	} else if !valid { // Not valid
		s.config.Services.Log.Error(ErrInvalidAlerts.Error())
		return ErrInvalidAlerts
	}

	// Serialize the alert data and hash
	a.SerializeData()

	// Execute the alert. An alert with valid signatures is authentic even when this
	// build cannot handle it (unknown type, or a payload rejected by a stricter parser),
	// so it is stored unprocessed for the retry cron and the chain advances rather than
	// stalling every node on this build at this sequence.
	a.Processed = true
	if err = a.Execute(s.ctx); err != nil {
		s.config.Services.Log.Errorf("failed to process alert %d; err: %v", a.SequenceNumber, err.Error())
		a.Processed = false
	}

	// Save the alert
	if err = a.Save(s.ctx); err != nil {
		return err
	}

	// Update the latest sequence
	s.myLatestSequence = a.SequenceNumber
	if s.myLatestSequence == s.latestSequence {
		s.config.Services.Log.Infof("successfully synced up to sequence %d", s.latestSequence)
		_ = s.stream.Close()
		return nil
	}

	// need to get the next sequence
	res := SyncMessage{
		Type:           IWantSequenceNumber,
		SequenceNumber: a.SequenceNumber + 1,
	}
	writer := util.NewWriter()
	writer.WriteIntBytes(res.Serialize())
	_, err = s.stream.Write(writer.Buf)
	return err
}

// ProcessWantSequenceNumber will process the want sequence number message
func (s *StreamThread) ProcessWantSequenceNumber(ctx context.Context, msg *SyncMessage) error {
	a, err := models.GetAlertMessageBySequenceNumber(ctx, msg.SequenceNumber, model.WithAllDependencies(s.config))
	if err != nil {
		s.config.Services.Log.Errorf("failed to get latest alert to send to peer: %s", err.Error())
		return err
	} else if a == nil {
		s.config.Services.Log.Error(ErrAlertNotFoundBySequence.Error())
		return ErrAlertNotFoundBySequence
	}
	var data []byte
	if data, err = hex.DecodeString(a.Raw); err != nil {
		s.config.Services.Log.Errorf("failed to decode raw alert data: %s", err.Error())
		return err
	}
	res := SyncMessage{
		Type:           IGotSequenceNumber,
		SequenceNumber: a.SequenceNumber,
		Data:           data,
	}
	writer := util.NewWriter()
	writer.WriteIntBytes(res.Serialize())
	_, err = s.stream.Write(writer.Buf)
	return err
}

// ProcessWantLatest will process the want latest message
func (s *StreamThread) ProcessWantLatest(ctx context.Context) error {
	a, err := models.GetLatestAlert(ctx, nil, model.WithAllDependencies(s.config))
	if err != nil {
		s.config.Services.Log.Errorf("failed to get latest alert to send to peer: %s", err.Error())
		return err
	} else if a == nil {
		s.config.Services.Log.Error(ErrAlertNotLatest.Error())
		return ErrAlertNotLatest
	}
	s.myLatestSequence = a.SequenceNumber

	var data []byte
	if data, err = hex.DecodeString(a.Raw); err != nil {
		s.config.Services.Log.Errorf("failed to decode raw alert data: %s", err.Error())
		return err
	}
	res := SyncMessage{
		Type:           IGotLatest,
		SequenceNumber: a.SequenceNumber,
		Data:           data,
	}
	writer := util.NewWriter()
	writer.WriteIntBytes(res.Serialize())
	_, err = s.stream.Write(writer.Buf)
	return err
}

// maxSyncMessageBytes returns the maximum size, in bytes, of a single sync frame this
// thread will read from a peer stream, falling back to the default when unconfigured.
func (s *StreamThread) maxSyncMessageBytes() uint64 {
	if s.config != nil && s.config.P2P.MaxMessageSizeBytes > 0 {
		return uint64(s.config.P2P.MaxMessageSizeBytes)
	}
	return config.DefaultP2PMaxMessageSizeBytes
}

// syncTimeout returns the maximum duration allowed for a single peer sync exchange,
// falling back to the default when unconfigured.
func (s *StreamThread) syncTimeout() time.Duration {
	if s.config != nil && s.config.P2P.SyncTimeout > 0 {
		return s.config.P2P.SyncTimeout
	}
	return config.DefaultSyncTimeout
}

// readSyncFrame reads a single length-prefixed sync frame from r. It rejects a frame
// whose declared length exceeds maxSize before allocating, so a malicious peer cannot
// drive an unbounded allocation or overflow make and crash the process. A zero maxSize
// falls back to the default. On any error it returns a nil buffer.
func readSyncFrame(r io.Reader, maxSize uint64) ([]byte, error) {
	if maxSize == 0 {
		maxSize = config.DefaultP2PMaxMessageSizeBytes
	}
	// Clamp the effective limit to the platform's maximum int so a length that passes the
	// size check below can never overflow make and panic (len out of range), even on a
	// 32-bit platform or when a caller supplies a limit larger than an int can hold.
	if maxInt := uint64(^uint(0) >> 1); maxSize > maxInt {
		maxSize = maxInt
	}
	var vi util.VarInt
	if _, err := vi.ReadFrom(r); err != nil {
		return nil, err
	}
	if vi > util.VarInt(maxSize) {
		return nil, fmt.Errorf("%w: %d bytes exceeds max %d", ErrSyncMessageTooLarge, uint64(vi), maxSize)
	}
	b := make([]byte, vi)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
