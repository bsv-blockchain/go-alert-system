package models

import (
	"encoding/binary"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/stretchr/testify/require"
)

// FuzzAlertMessageBanPeerRead tests ban peer alert parsing
func FuzzAlertMessageBanPeerRead(f *testing.F) {
	// Seed with valid ban peer message: VarInt(peerLen) + peer + VarInt(reasonLen) + reason
	validMsg := make([]byte, 0)
	peerData := []byte("192.168.1.1:8333")
	reasonData := []byte("malicious behavior")

	// Add peer length and data
	w := util.NewWriter()
	w.WriteVarInt(uint64(len(peerData)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, peerData...)

	// Add reason length and data
	w = util.NewWriter()
	w.WriteVarInt(uint64(len(reasonData)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, reasonData...)

	f.Add(validMsg)

	// Seed with edge cases
	f.Add([]byte{})                 // empty
	f.Add([]byte{0x00})             // zero length peer
	f.Add([]byte{0x01, 0x41})       // 1 byte peer 'A'
	f.Add([]byte{0x01, 0x41, 0x00}) // peer + zero reason

	// Seed with large values
	largeMsg := make([]byte, 0)
	w = util.NewWriter()
	w.WriteVarInt(100)
	largeMsg = append(largeMsg, w.Buf...)
	largeMsg = append(largeMsg, make([]byte, 100)...) // 100 byte peer
	w = util.NewWriter()
	w.WriteVarInt(100)
	largeMsg = append(largeMsg, w.Buf...)
	largeMsg = append(largeMsg, make([]byte, 100)...) // 100 byte reason
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
		require.LessOrEqual(t, alert.PeerLength, uint64(len(data)), "peer length should not exceed data length")
		require.LessOrEqual(t, alert.ReasonLength, uint64(len(data)), "reason length should not exceed data length")
		require.Equal(t, alert.PeerLength, uint64(len(alert.Peer)), "peer length should match peer data")
		require.Equal(t, alert.ReasonLength, uint64(len(alert.Reason)), "reason length should match reason data")
	})
}

// FuzzAlertMessageUnbanPeerRead tests unban peer alert parsing
func FuzzAlertMessageUnbanPeerRead(f *testing.F) {
	// Seed with valid unban peer message (same structure as ban)
	validMsg := make([]byte, 0)
	peerData := []byte("192.168.1.1:8333")
	reasonData := []byte("false positive")

	w := util.NewWriter()
	w.WriteVarInt(uint64(len(peerData)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, peerData...)

	w = util.NewWriter()
	w.WriteVarInt(uint64(len(reasonData)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, reasonData...)

	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x01, 0x41})
	f.Add([]byte{0x01, 0x41, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageUnbanPeer{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate parsed data
		require.LessOrEqual(t, alert.PeerLength, uint64(len(data)), "peer length should not exceed data length")
		require.LessOrEqual(t, alert.ReasonLength, uint64(len(data)), "reason length should not exceed data length")
	})
}

// FuzzAlertMessageInformationalRead tests informational alert parsing
func FuzzAlertMessageInformationalRead(f *testing.F) {
	// Seed with valid informational message
	validMsg := make([]byte, 0)
	message := []byte("System maintenance scheduled")

	w := util.NewWriter()
	w.WriteVarInt(uint64(len(message)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, message...)

	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})           // empty
	f.Add([]byte{0x00})       // zero length message
	f.Add([]byte{0x01, 0x41}) // single character 'A'

	// Invalid: length exceeds data
	invalidLen := make([]byte, 0)
	w = util.NewWriter()
	w.WriteVarInt(100) // claim 100 bytes
	invalidLen = append(invalidLen, w.Buf...)
	invalidLen = append(invalidLen, []byte{0x01}...) // but only 1 byte
	f.Add(invalidLen)

	// Valid with extra bytes (should trigger IsComplete check)
	extraBytes := make([]byte, 0)
	w = util.NewWriter()
	w.WriteVarInt(5)
	extraBytes = append(extraBytes, w.Buf...)
	extraBytes = append(extraBytes, []byte("hello")...)
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
		require.Equal(t, alert.MessageLength, uint64(len(alert.Message)), "message length should match message data")
		require.LessOrEqual(t, alert.MessageLength, uint64(len(data)), "message length should not exceed input data")
	})
}

// FuzzAlertMessageFreezeUtxoRead tests freeze UTXO alert parsing
func FuzzAlertMessageFreezeUtxoRead(f *testing.F) {
	// Seed with valid freeze message (57 bytes per fund)
	validMsg := make([]byte, 57)
	// txid (32 bytes) + vout (8) + start height (8) + end height (8) + expire flag (1) = 57
	copy(validMsg[0:32], make([]byte, 32))                 // txid
	binary.LittleEndian.PutUint64(validMsg[32:40], 0)      // vout
	binary.LittleEndian.PutUint64(validMsg[40:48], 100000) // start height
	binary.LittleEndian.PutUint64(validMsg[48:56], 200000) // end height
	validMsg[56] = 1                                       // expire flag

	f.Add(validMsg)

	// Multiple funds (114 bytes = 2 funds)
	multipleMsg := make([]byte, 114)
	copy(multipleMsg[0:57], validMsg)
	copy(multipleMsg[57:114], validMsg)
	f.Add(multipleMsg)

	// Edge cases
	f.Add([]byte{})          // empty
	f.Add(make([]byte, 56))  // one byte short
	f.Add(make([]byte, 58))  // one byte over (not divisible by 57)
	f.Add(make([]byte, 57))  // minimum valid (all zeros)
	f.Add(make([]byte, 171)) // 3 funds

	// Test with max int values to trigger overflow check
	overflowMsg := make([]byte, 57)
	copy(overflowMsg[0:32], make([]byte, 32))
	binary.LittleEndian.PutUint64(overflowMsg[32:40], ^uint64(0)) // max uint64 for vout
	binary.LittleEndian.PutUint64(overflowMsg[40:48], 100000)
	binary.LittleEndian.PutUint64(overflowMsg[48:56], 200000)
	overflowMsg[56] = 0
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
			require.LessOrEqual(t, fund.EnforceAtHeight[0].Start, int(^uint(0)>>1), "start height should not overflow int")
			require.LessOrEqual(t, fund.EnforceAtHeight[0].Stop, int(^uint(0)>>1), "end height should not overflow int")
		}
	})
}

// FuzzAlertMessageUnfreezeUtxoRead tests unfreeze UTXO alert parsing
func FuzzAlertMessageUnfreezeUtxoRead(f *testing.F) {
	// Same structure as freeze UTXO (57 bytes per fund)
	validMsg := make([]byte, 57)
	copy(validMsg[0:32], make([]byte, 32))
	binary.LittleEndian.PutUint64(validMsg[32:40], 0)
	binary.LittleEndian.PutUint64(validMsg[40:48], 100000)
	binary.LittleEndian.PutUint64(validMsg[48:56], 200000)
	validMsg[56] = 0

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
	validMsg := make([]byte, 0)
	heightBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(heightBytes[0:8], 100000) // enforce at height
	validMsg = append(validMsg, heightBytes...)

	txHex := []byte("0100000001...")
	w := util.NewWriter()
	w.WriteVarInt(uint64(len(txHex)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, txHex...)

	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})        // empty
	f.Add(make([]byte, 8)) // only height, no tx
	f.Add(make([]byte, 9)) // height + varint start

	// Minimum valid: height + zero-length tx
	minMsgHeight := make([]byte, 8)
	binary.LittleEndian.PutUint64(minMsgHeight[0:8], 0)
	minMsg := append([]byte(nil), minMsgHeight...)
	minMsg = append(minMsg, 0x00) // zero length varint
	f.Add(minMsg)

	// Test max int64 overflow
	overflowMsgHeight := make([]byte, 8)
	binary.LittleEndian.PutUint64(overflowMsgHeight[0:8], ^uint64(0)) // max uint64
	overflowMsg := append([]byte(nil), overflowMsgHeight...)
	overflowMsg = append(overflowMsg, 0x00)
	f.Add(overflowMsg)

	// Length exceeds data
	badLenMsgHeight := make([]byte, 8)
	binary.LittleEndian.PutUint64(badLenMsgHeight[0:8], 100000)
	w = util.NewWriter()
	w.WriteVarInt(100) // claim 100 bytes
	badLenMsg := append([]byte(nil), badLenMsgHeight...)
	badLenMsg = append(badLenMsg, w.Buf...)
	badLenMsg = append(badLenMsg, []byte{0x01}...) // but only 1 byte
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
	// Fill with a sample block hash
	copy(blockHashBytes[0:32], []byte("blockhash123456789012345678901"))
	validMsg := append([]byte(nil), blockHashBytes...)

	reason := []byte("invalid proof of work")
	w := util.NewWriter()
	w.WriteVarInt(uint64(len(reason)))
	validMsg = append(validMsg, w.Buf...)
	validMsg = append(validMsg, reason...)

	f.Add(validMsg)

	// Edge cases
	f.Add([]byte{})         // empty
	f.Add(make([]byte, 31)) // hash too short
	f.Add(make([]byte, 32)) // only hash
	f.Add(make([]byte, 33)) // hash + varint start

	// Minimum valid: hash + zero reason
	minMsgHash := make([]byte, 32)
	minMsgInvalidate := append([]byte(nil), minMsgHash...)
	minMsgInvalidate = append(minMsgInvalidate, 0x00) // zero length reason
	f.Add(minMsgInvalidate)

	f.Fuzz(func(t *testing.T, data []byte) {
		alert := &AlertMessageInvalidateBlock{}

		// Should never panic
		err := alert.Read(data)
		if err != nil {
			return
		}

		// Validate successful parse
		require.Len(t, alert.BlockHash, 32, "block hash should be 32 bytes")
		require.Equal(t, alert.ReasonLength, uint64(len(alert.Reason)), "reason length should match reason data")
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
