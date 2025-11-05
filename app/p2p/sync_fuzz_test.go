package p2p

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzNewSyncMessageFromBytes tests P2P sync message parsing
func FuzzNewSyncMessageFromBytes(f *testing.F) {
	// Seed with valid IWantLatest message (type only, no sequence)
	f.Add([]byte{IWantLatest})

	// Seed with valid IWantSequenceNumber message (type + sequence + optional data)
	wantSeqMsg := []byte{IWantSequenceNumber}
	wantSeqMsg = binary.LittleEndian.AppendUint32(wantSeqMsg, 12345)
	f.Add(wantSeqMsg)

	// Seed with valid IGotSequenceNumber message
	gotSeqMsg := []byte{IGotSequenceNumber}
	gotSeqMsg = binary.LittleEndian.AppendUint32(gotSeqMsg, 67890)
	gotSeqMsg = append(gotSeqMsg, []byte("alert data here")...)
	f.Add(gotSeqMsg)

	// Seed with valid IGotLatest message
	gotLatestMsg := []byte{IGotLatest}
	gotLatestMsg = binary.LittleEndian.AppendUint32(gotLatestMsg, 99999)
	gotLatestMsg = append(gotLatestMsg, []byte("latest alert data")...)
	f.Add(gotLatestMsg)

	// Seed with edge cases
	f.Add([]byte{})                                      // empty
	f.Add([]byte{0x00})                                  // unknown type, no sequence
	f.Add([]byte{0xFF})                                  // invalid type
	f.Add([]byte{IWantSequenceNumber})                   // type without required sequence
	f.Add([]byte{IWantSequenceNumber, 0x01})             // type with partial sequence
	f.Add([]byte{IWantSequenceNumber, 0x01, 0x02})       // type with partial sequence
	f.Add([]byte{IWantSequenceNumber, 0x01, 0x02, 0x03}) // type with partial sequence

	// Seed with minimum valid non-IWantLatest (5 bytes: type + 4 byte sequence)
	minMsg := make([]byte, 5)
	minMsg[0] = IGotSequenceNumber
	binary.LittleEndian.PutUint32(minMsg[1:5], 0)
	f.Add(minMsg)

	// Seed with maximum uint32 sequence number
	maxSeqMsg := []byte{IGotSequenceNumber}
	maxSeqMsg = binary.LittleEndian.AppendUint32(maxSeqMsg, ^uint32(0))
	f.Add(maxSeqMsg)

	// Seed with large data payload
	largeMsg := []byte{IGotLatest}
	largeMsg = binary.LittleEndian.AppendUint32(largeMsg, 12345)
	largeMsg = append(largeMsg, make([]byte, 1000)...) // 1KB data
	f.Add(largeMsg)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic
		msg, err := NewSyncMessageFromBytes(data)
		if err != nil {
			// Error is acceptable for invalid input
			require.Nil(t, msg, "message should be nil when error is returned")
			return
		}

		// If no error, validate the parsed message
		require.NotNil(t, msg, "message should not be nil when no error")

		// Type should be set
		require.GreaterOrEqual(t, len(data), 1, "data should have at least 1 byte for type")
		require.Equal(t, data[0], msg.Type, "type should match first byte")

		// If type is IWantLatest, no sequence number is required
		if msg.Type == IWantLatest {
			require.Equal(t, uint32(0), msg.SequenceNumber, "sequence should be 0 for IWantLatest")
			require.Nil(t, msg.Data, "data should be nil for IWantLatest")
			return
		}

		// For other types, sequence number should be present
		require.GreaterOrEqual(t, len(data), 5, "data should have at least 5 bytes for non-IWantLatest types")

		// Validate sequence number is correctly parsed
		expectedSeq := binary.LittleEndian.Uint32(data[1:5])
		require.Equal(t, expectedSeq, msg.SequenceNumber, "sequence number should match bytes 1-4")

		// Validate data field
		if len(data) > 5 {
			require.Equal(t, data[5:], msg.Data, "data should match remaining bytes")
		} else {
			require.Empty(t, msg.Data, "data should be empty when no extra bytes")
		}
	})
}

// FuzzSyncMessageSerialize tests round-trip serialization consistency
func FuzzSyncMessageSerialize(f *testing.F) {
	// Seed with various message types
	f.Add(byte(IWantLatest), uint32(0), []byte{})
	f.Add(byte(IWantSequenceNumber), uint32(12345), []byte{})
	f.Add(byte(IGotSequenceNumber), uint32(67890), []byte("alert data"))
	f.Add(byte(IGotLatest), uint32(99999), []byte("latest alert"))
	f.Add(byte(0x00), uint32(0), []byte{})
	f.Add(byte(0xFF), ^uint32(0), make([]byte, 100))

	f.Fuzz(func(t *testing.T, msgType byte, seqNum uint32, data []byte) {
		// Create sync message
		msg := &SyncMessage{
			Type:           msgType,
			SequenceNumber: seqNum,
			Data:           data,
		}

		// Serialize should never panic
		serialized := msg.Serialize()

		// Validate serialization
		require.NotNil(t, serialized, "serialization should produce output")
		require.GreaterOrEqual(t, len(serialized), 5, "serialized message should have at least 5 bytes")

		// Validate format: type(1) + sequence(4) + data
		require.Equal(t, msgType, serialized[0], "first byte should be type")
		parsedSeq := binary.LittleEndian.Uint32(serialized[1:5])
		require.Equal(t, seqNum, parsedSeq, "bytes 1-4 should be sequence number")

		if len(data) > 0 {
			require.Equal(t, data, serialized[5:], "remaining bytes should be data")
		}

		// Test round-trip consistency (serialize → deserialize)
		// Only test if the message type is IWantLatest or has enough data
		if msgType == IWantLatest {
			// For IWantLatest, we can deserialize from just the type byte
			deserialized, err := NewSyncMessageFromBytes([]byte{msgType})
			if err == nil {
				require.Equal(t, msgType, deserialized.Type, "deserialized type should match")
			}
		} else {
			// For other types, deserialize from full serialized data
			deserialized, err := NewSyncMessageFromBytes(serialized)
			if err == nil {
				require.Equal(t, msgType, deserialized.Type, "deserialized type should match")
				require.Equal(t, seqNum, deserialized.SequenceNumber, "deserialized sequence should match")
				require.Equal(t, data, deserialized.Data, "deserialized data should match")
			}
		}
	})
}

// FuzzSyncMessageTypes tests handling of different message type values
func FuzzSyncMessageTypes(f *testing.F) {
	// Seed with known message types
	f.Add(byte(IWantLatest))
	f.Add(byte(IWantSequenceNumber))
	f.Add(byte(IGotSequenceNumber))
	f.Add(byte(IGotLatest))

	// Seed with boundary values
	f.Add(byte(0x00))
	f.Add(byte(0xFF))
	f.Add(byte(0x7F))
	f.Add(byte(0x80))

	f.Fuzz(func(t *testing.T, msgType byte) {
		// Test with just the type byte
		msg1, err1 := NewSyncMessageFromBytes([]byte{msgType})

		// IWantLatest (0x01) should succeed with just 1 byte
		if msgType == IWantLatest {
			require.NoError(t, err1, "IWantLatest should parse with just 1 byte")
			require.NotNil(t, msg1, "message should not be nil for IWantLatest")
			require.Equal(t, msgType, msg1.Type, "type should match")
			return
		}

		// All other types should fail with just 1 byte (need 5 bytes minimum)
		require.Error(t, err1, "non-IWantLatest types should fail with just 1 byte")
		require.Nil(t, msg1, "message should be nil on error")

		// Test with full 5 byte message
		fullMsg := []byte{msgType, 0x01, 0x02, 0x03, 0x04}
		msg2, err2 := NewSyncMessageFromBytes(fullMsg)

		// Should succeed with 5 bytes regardless of type
		require.NoError(t, err2, "should parse with 5 bytes")
		require.NotNil(t, msg2, "message should not be nil with 5 bytes")
		require.Equal(t, msgType, msg2.Type, "type should match")
	})
}
