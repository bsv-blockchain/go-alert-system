package models

import (
	"encoding/binary"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

// Helper functions for fuzz tests

// buildVarIntMessage builds a message from multiple parts, each prefixed with its length as a VarInt
func buildVarIntMessage(parts ...[]byte) []byte {
	// Estimate capacity: each part has up to 9 bytes for VarInt + the part data
	totalLen := 0
	for _, part := range parts {
		totalLen += 9 + len(part) // max VarInt size + data
	}
	msg := make([]byte, 0, totalLen)
	for _, part := range parts {
		w := util.NewWriter()
		w.WriteVarInt(uint64(len(part)))
		msg = append(msg, w.Buf...)
		msg = append(msg, part...)
	}
	return msg
}

// addCommonEdgeCases adds standard edge case seeds to the fuzz corpus
func addCommonEdgeCases(f *testing.F) {
	f.Add([]byte{})                 // empty
	f.Add([]byte{0x00})             // zero length
	f.Add([]byte{0x01, 0x41})       // 1 byte 'A'
	f.Add([]byte{0x01, 0x41, 0x00}) // with zero terminator
}

// assertLengthFieldValid validates that a length field matches actual data and doesn't exceed input
func assertLengthFieldValid(t *testing.T, lengthField uint64, actualData, inputData []byte, fieldName string) {
	require.LessOrEqual(t, lengthField, uint64(len(inputData)), "%s length should not exceed data length", fieldName)
	require.Equal(t, lengthField, uint64(len(actualData)), "%s length should match %s data", fieldName, fieldName)
}

// buildUtxoAlertMessage builds a 57-byte UTXO freeze/unfreeze alert message
func buildUtxoAlertMessage(vout, startHeight, endHeight uint64, expireFlag byte) []byte {
	msg := make([]byte, 57)
	copy(msg[0:32], make([]byte, 32)) // txid (32 bytes zero-filled)
	binary.LittleEndian.PutUint64(msg[32:40], vout)
	binary.LittleEndian.PutUint64(msg[40:48], startHeight)
	binary.LittleEndian.PutUint64(msg[48:56], endHeight)
	msg[56] = expireFlag
	return msg
}

// buildHeightPlusVarIntMessage builds a message with an 8-byte height followed by VarInt-prefixed data
func buildHeightPlusVarIntMessage(height uint64, data []byte) []byte {
	heightBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBytes[0:8], height)
	w := util.NewWriter()
	w.WriteVarInt(uint64(len(data)))
	msg := make([]byte, 0, 8+len(w.Buf)+len(data))
	msg = append(msg, heightBytes...)
	msg = append(msg, w.Buf...)
	msg = append(msg, data...)
	return msg
}

// buildFixedPrefixVarIntMessage builds a message with a fixed prefix followed by VarInt-prefixed data
func buildFixedPrefixVarIntMessage(prefix, data []byte) []byte {
	msg := append([]byte(nil), prefix...)
	w := util.NewWriter()
	w.WriteVarInt(uint64(len(data)))
	msg = append(msg, w.Buf...)
	msg = append(msg, data...)
	return msg
}

// FuzzAlertMessageBanPeerRead tests ban peer alert parsing
func FuzzAlertMessageBanPeerRead(f *testing.F) {
	// Seed with valid ban peer message: VarInt(peerLen) + peer + VarInt(reasonLen) + reason
	peerData := []byte("192.168.1.1:8333")
	reasonData := []byte("malicious behavior")
	validMsg := buildVarIntMessage(peerData, reasonData)
	f.Add(validMsg)

	// Seed with edge cases
	addCommonEdgeCases(f)

	// Seed with large values
	largeMsg := buildVarIntMessage(make([]byte, 100), make([]byte, 100))
	f.Add(largeMsg)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageBanPeer{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			// Error is acceptable
			return
		}

		// If successful, validate the parsed data
		assertLengthFieldValid(t, alert.PeerLength, alert.Peer, data, "peer")
		assertLengthFieldValid(t, alert.ReasonLength, alert.Reason, data, "reason")
	})
}

// FuzzAlertMessageUnbanPeerRead tests unban peer alert parsing
func FuzzAlertMessageUnbanPeerRead(f *testing.F) {
	// Seed with valid unban peer message (same structure as ban)
	peerData := []byte("192.168.1.1:8333")
	reasonData := []byte("false positive")
	validMsg := buildVarIntMessage(peerData, reasonData)
	f.Add(validMsg)

	// Edge cases
	addCommonEdgeCases(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageUnbanPeer{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate parsed data
		assertLengthFieldValid(t, alert.PeerLength, alert.Peer, data, "peer")
		assertLengthFieldValid(t, alert.ReasonLength, alert.Reason, data, "reason")
	})
}

// FuzzAlertMessageInformationalRead tests informational alert parsing
func FuzzAlertMessageInformationalRead(f *testing.F) {
	// Seed with valid informational message
	message := []byte("System maintenance scheduled")
	validMsg := buildVarIntMessage(message)
	f.Add(validMsg)

	// Edge cases
	addCommonEdgeCases(f)

	// Invalid: length exceeds data
	invalidLen := buildVarIntMessage(make([]byte, 100))
	invalidLen = append(invalidLen[:len(invalidLen)-99], 0x01) // claim 100 bytes but only 1 byte
	f.Add(invalidLen)

	// Valid with extra bytes (should trigger IsComplete check)
	extraBytes := buildVarIntMessage([]byte("hello"))
	extraBytes = append(extraBytes, []byte("extra")...) // extra bytes
	f.Add(extraBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageInformational{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		assertLengthFieldValid(t, alert.MessageLength, alert.Message, data, "message")
	})
}

// FuzzAlertMessageFreezeUtxoRead tests freeze UTXO alert parsing
func FuzzAlertMessageFreezeUtxoRead(f *testing.F) {
	// Seed with valid freeze message (57 bytes per fund)
	// txid (32 bytes) + vout (8) + start height (8) + end height (8) + expire flag (1) = 57
	validMsg := buildUtxoAlertMessage(0, 100000, 200000, 1)
	f.Add(validMsg)

	// Multiple funds (114 bytes = 2 funds)
	multipleMsg := append(validMsg, validMsg...)
	f.Add(multipleMsg)

	// Edge cases
	f.Add([]byte{})          // empty
	f.Add(make([]byte, 56))  // one byte short
	f.Add(make([]byte, 58))  // one byte over (not divisible by 57)
	f.Add(make([]byte, 57))  // minimum valid (all zeros)
	f.Add(make([]byte, 171)) // 3 funds

	// Test with max int values to trigger overflow check
	overflowMsg := buildUtxoAlertMessage(^uint64(0), 100000, 200000, 0)
	f.Add(overflowMsg)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageFreezeUtxo{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		expectedFunds := len(data) / 57
		require.Len(t, alert.Funds, expectedFunds, "number of funds should match data length / 57")

		// Validate no overflow occurred
		for _, fund := range alert.Funds {
			require.GreaterOrEqual(t, fund.TxOut.Vout, 0, "vout should be non-negative")
			require.NotEmpty(t, fund.EnforceAtHeight, "EnforceAtHeight should not be empty")
			require.LessOrEqual(t, fund.EnforceAtHeight[0].Start, int(^uint(0)>>1), "start height should not overflow int")
			require.LessOrEqual(t, fund.EnforceAtHeight[0].Stop, int(^uint(0)>>1), "end height should not overflow int")
		}
	})
}

// FuzzAlertMessageUnfreezeUtxoRead tests unfreeze UTXO alert parsing
func FuzzAlertMessageUnfreezeUtxoRead(f *testing.F) {
	// Same structure as freeze UTXO (57 bytes per fund)
	validMsg := buildUtxoAlertMessage(0, 100000, 200000, 0)
	f.Add(validMsg)
	f.Add([]byte{})
	f.Add(make([]byte, 56))
	f.Add(make([]byte, 58))
	f.Add(make([]byte, 114))

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageUnfreezeUtxo{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		expectedFunds := len(data) / 57
		require.Len(t, alert.Funds, expectedFunds, "number of funds should match data length / 57")
	})
}

// FuzzAlertMessageConfiscateTransactionRead tests confiscate transaction alert parsing
func FuzzAlertMessageConfiscateTransactionRead(f *testing.F) {
	// Seed with valid confiscation message: height(8) + VarInt(hexLen) + hex
	txHex := []byte("0100000001...")
	validMsg := buildHeightPlusVarIntMessage(100000, txHex)
	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})        // empty
	f.Add(make([]byte, 8)) // only height, no tx
	f.Add(make([]byte, 9)) // height + varint start

	// Minimum valid: height + zero-length tx
	minMsg := buildHeightPlusVarIntMessage(0, []byte{})
	f.Add(minMsg)

	// Test max int64 overflow
	overflowMsg := buildHeightPlusVarIntMessage(^uint64(0), []byte{})
	f.Add(overflowMsg)

	// Length exceeds data
	badLenMsg := buildHeightPlusVarIntMessage(100000, make([]byte, 100))
	badLenMsg = append(badLenMsg[:len(badLenMsg)-99], 0x01) // claim 100 bytes but only 1 byte
	f.Add(badLenMsg)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageConfiscateTransaction{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		require.Len(t, alert.Transactions, 1, "should parse exactly one transaction")
		require.GreaterOrEqual(t, alert.Transactions[0].ConfiscationTransaction.EnforceAtHeight, int64(0), "height should be non-negative")
		// Hex can be empty (zero-length transaction is valid in the parser)
	})
}

// FuzzAlertMessageInvalidateBlockRead tests invalidate block alert parsing
func FuzzAlertMessageInvalidateBlockRead(f *testing.F) {
	// Seed with valid invalidate block message: blockHash(32) + VarInt(reasonLen) + reason
	blockHashBytes := make([]byte, 32)
	copy(blockHashBytes[0:32], []byte("blockhash123456789012345678901"))
	reason := []byte("invalid proof of work")
	validMsg := buildFixedPrefixVarIntMessage(blockHashBytes, reason)
	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})         // empty
	f.Add(make([]byte, 31)) // hash too short
	f.Add(make([]byte, 32)) // only hash
	f.Add(make([]byte, 33)) // hash + varint start

	// Minimum valid: hash + zero reason
	minMsg := buildFixedPrefixVarIntMessage(make([]byte, 32), []byte{})
	f.Add(minMsg)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageInvalidateBlock{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		require.Len(t, alert.BlockHash, 32, "block hash should be 32 bytes")
		assertLengthFieldValid(t, alert.ReasonLength, alert.Reason, data, "reason")
	})
}

// FuzzAlertMessageSetKeysRead tests set keys alert parsing
func FuzzAlertMessageSetKeysRead(f *testing.F) {
	// Seed with valid set keys message: exactly 165 bytes (5 keys × 33 bytes)
	validMsg := make([]byte, 165)
	// Fill with sample public keys (33 bytes each)
	for i := 0; i < 5; i++ {
		validMsg[i*33] = 0x02 // compressed public key prefix
		for j := 1; j < 33; j++ {
			validMsg[i*33+j] = byte(i + j)
		}
	}

	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})          // empty
	f.Add(make([]byte, 164)) // one byte short
	f.Add(make([]byte, 165)) // exact length (all zeros)
	f.Add(make([]byte, 166)) // one byte over
	f.Add(make([]byte, 33))  // single key
	f.Add(make([]byte, 100)) // arbitrary length

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageSetKeys{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		require.Len(t, alert.Keys, 5, "should parse exactly 5 keys")
		for _, key := range alert.Keys {
			require.Len(t, key, 33, "each key should be 33 bytes")
		}
	})
}
