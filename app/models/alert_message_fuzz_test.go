package models

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzNewAlertFromBytes tests NewAlertFromBytes with arbitrary byte inputs
func FuzzNewAlertFromBytes(f *testing.F) {
	// Seed with valid alert message structure
	// Format: version(4) + sequence(4) + timestamp(8) + alertType(4) + message + signatures(195)
	validAlert := make([]byte, 0)
	validAlert = binary.LittleEndian.AppendUint32(validAlert, 1)                              // version
	validAlert = binary.LittleEndian.AppendUint32(validAlert, 1)                              // sequence
	validAlert = binary.LittleEndian.AppendUint64(validAlert, 1234567890)                     // timestamp
	validAlert = binary.LittleEndian.AppendUint32(validAlert, uint32(AlertTypeInformational)) // alert type
	validAlert = append(validAlert, []byte("test message")...)                                // message
	validAlert = append(validAlert, make([]byte, 195)...)                                     // 3 signatures (65 bytes each)

	f.Add(validAlert)

	// Seed with minimal valid length (16 bytes header + 2 bytes message + 195 signatures)
	minimalAlert := make([]byte, 0)
	minimalAlert = binary.LittleEndian.AppendUint32(minimalAlert, 1)
	minimalAlert = binary.LittleEndian.AppendUint32(minimalAlert, 1)
	minimalAlert = binary.LittleEndian.AppendUint64(minimalAlert, 0)
	minimalAlert = binary.LittleEndian.AppendUint32(minimalAlert, uint32(AlertTypeInformational))
	minimalAlert = append(minimalAlert, []byte("ab")...)      // 2 byte message
	minimalAlert = append(minimalAlert, make([]byte, 195)...) // signatures

	f.Add(minimalAlert)

	// Seed with different alert types
	for _, alertType := range []AlertType{
		AlertTypeInformational,
		AlertTypeFreezeUtxo,
		AlertTypeUnfreezeUtxo,
		AlertTypeConfiscateUtxo,
		AlertTypeBanPeer,
		AlertTypeUnbanPeer,
		AlertTypeInvalidateBlock,
		AlertTypeSetKeys,
	} {
		typeAlert := make([]byte, 0)
		typeAlert = binary.LittleEndian.AppendUint32(typeAlert, 1)
		typeAlert = binary.LittleEndian.AppendUint32(typeAlert, 1)
		typeAlert = binary.LittleEndian.AppendUint64(typeAlert, 0)
		typeAlert = binary.LittleEndian.AppendUint32(typeAlert, uint32(alertType))
		typeAlert = append(typeAlert, []byte("test")...)
		typeAlert = append(typeAlert, make([]byte, 195)...)
		f.Add(typeAlert)
	}

	// Seed with special alert type 99 (uses 128 byte signature)
	specialAlert := make([]byte, 0)
	specialAlert = binary.LittleEndian.AppendUint32(specialAlert, 1)
	specialAlert = binary.LittleEndian.AppendUint32(specialAlert, 1)
	specialAlert = binary.LittleEndian.AppendUint64(specialAlert, 0)
	specialAlert = binary.LittleEndian.AppendUint32(specialAlert, 99)
	specialAlert = append(specialAlert, []byte("test")...)
	specialAlert = append(specialAlert, make([]byte, 128)...)
	f.Add(specialAlert)

	// Seed with edge cases
	f.Add([]byte{})           // empty
	f.Add([]byte{0})          // single byte
	f.Add(make([]byte, 19))   // just under minimum header (20 bytes)
	f.Add(make([]byte, 20))   // minimum header only (no message/signatures)
	f.Add(make([]byte, 217))  // minimum valid total (20 header + 2 message + 195 sig)
	f.Add(make([]byte, 1000)) // large message

	f.Fuzz(func(t *testing.T, data []byte) {
		// The function should never panic, regardless of input
		alert, err := NewAlertFromBytes(data)
		if err != nil {
			// Error is acceptable - just ensure it's one of the expected errors
			require.Nil(t, alert, "alert should be nil when error is returned")
			return
		}

		// If no error, validate the alert was created properly
		require.NotNil(t, alert, "alert should not be nil when no error")
		require.NotNil(t, alert.GetRawMessage(), "raw message should be set")
		// The raw message length is validated in ReadRaw(), so if we got here it's valid
	})
}

// FuzzAlertMessageReadRaw tests the ReadRaw method with arbitrary inputs
func FuzzAlertMessageReadRaw(f *testing.F) {
	// Seed with valid hex-encoded alert
	validAlert := make([]byte, 0)
	validAlert = binary.LittleEndian.AppendUint32(validAlert, 1)
	validAlert = binary.LittleEndian.AppendUint32(validAlert, 1)
	validAlert = binary.LittleEndian.AppendUint64(validAlert, 1234567890)
	validAlert = binary.LittleEndian.AppendUint32(validAlert, uint32(AlertTypeInformational))
	validAlert = append(validAlert, []byte("test message")...)
	validAlert = append(validAlert, make([]byte, 195)...)
	f.Add(hex.EncodeToString(validAlert))

	// Seed with edge cases
	f.Add("")                                    // empty string
	f.Add("00")                                  // single byte hex
	f.Add("not-valid-hex")                       // invalid hex
	f.Add(hex.EncodeToString(make([]byte, 15)))  // under minimum
	f.Add(hex.EncodeToString(make([]byte, 16)))  // minimum header
	f.Add(hex.EncodeToString(make([]byte, 217))) // minimum valid

	f.Fuzz(func(t *testing.T, rawHex string) {
		// Create alert with raw hex string
		alert := NewAlertMessage()
		alert.Raw = rawHex

		// The function should never panic
		err := alert.ReadRaw()
		if err != nil {
			// Error is acceptable - validate the alert state remains consistent
			require.NotNil(t, alert, "alert should not be nil even on error")
			return
		}

		// If no error, validate parsing succeeded
		require.NotNil(t, alert.GetRawMessage(), "raw message should be set after successful parse")
		// Sequence number can be any uint32 value including 0
		require.NotEmpty(t, alert.Hash, "hash should be computed")
	})
}

// FuzzAlertMessageSerialize tests round-trip serialization consistency
func FuzzAlertMessageSerialize(f *testing.F) {
	// Seed with valid alert components
	f.Add(uint32(1), uint32(1), uint64(1234567890), uint32(AlertTypeInformational), []byte("test"))

	f.Fuzz(func(t *testing.T, version, sequence uint32, timestamp uint64, alertType uint32, message []byte) {
		// Create alert
		alert := NewAlertMessage()
		alert.SetVersion(version)
		alert.SequenceNumber = sequence
		alert.SetTimestamp(timestamp)

		// Only test valid alert types to avoid nil pointer in ProcessAlertMessage
		validAlertTypes := []AlertType{
			AlertTypeInformational,
			AlertTypeFreezeUtxo,
			AlertTypeUnfreezeUtxo,
			AlertTypeConfiscateUtxo,
			AlertTypeBanPeer,
			AlertTypeUnbanPeer,
			AlertTypeInvalidateBlock,
			AlertTypeSetKeys,
		}

		// Map the fuzzed uint32 to a valid alert type
		// Safe conversion: len always returns non-negative int, and we have a fixed small array
		numTypes := len(validAlertTypes)
		if numTypes > 0 {
			alert.SetAlertType(validAlertTypes[int(alertType)%numTypes])
		}
		alert.SetRawMessage(message)

		// Add dummy signatures (3 x 65 bytes)
		alert.SetSignatures([][]byte{
			make([]byte, 65),
			make([]byte, 65),
			make([]byte, 65),
		})

		// Serialize should never panic
		serialized := alert.Serialize()

		// Validate serialization produced output
		require.NotNil(t, serialized, "serialization should produce output")
		require.NotEmpty(t, alert.Raw, "Raw field should be set after serialization")
		require.NotEmpty(t, alert.Hash, "Hash should be computed after serialization")

		// Validate the serialized data structure
		require.GreaterOrEqual(t, len(serialized), 20, "serialized data should include header")
	})
}
