package models

import "errors"

// Static errors for the models package
var (
	// AlertMessage errors
	ErrNoActivePublicKeys        = errors.New("no active public keys found")
	ErrFailedToConvertPubKey     = errors.New("failed to convert pub key to address")
	ErrAlertTooShort             = errors.New("alert needs to be at least 16 bytes")
	ErrAlertMessageInvalidLength = errors.New("alert message is invalid - too short length")

	// AlertMessageBanPeer errors
	ErrFailedToReadPeer   = errors.New("failed to read peer")
	ErrFailedToReadReason = errors.New("failed to read reason")

	// AlertMessageConfiscateUtxo errors
	ErrConfiscationAlertTooShort = errors.New("confiscation alert is less than 9 bytes")
	ErrTxHexLengthTooLong        = errors.New("tx hex length is longer than the remaining buffer")
	ErrFailedToReadTxHex         = errors.New("failed to read tx hex")
	ErrConfiscationAlertRPCError = errors.New("confiscation alert RPC response returned an error")

	// AlertMessageFreezeUtxo errors
	ErrFreezeAlertTooShort        = errors.New("freeze alert is less than 57 bytes")
	ErrFreezeAlertInvalidLength   = errors.New("freeze alert is not a multiple of 57 bytes")
	ErrFailedToReadFundLength     = errors.New("failed to read fund length")
	ErrFailedToReadTxID           = errors.New("failed to read txid")
	ErrFailedToReadVout           = errors.New("failed to read vout")
	ErrFailedToReadEnforceAtStart = errors.New("failed to read enforce at height start")
	ErrFailedToReadEnforceAtEnd   = errors.New("failed to read enforce at height end")
	ErrFreezeAlertRPCError        = errors.New("freeze alert RPC response returned an error")

	// AlertMessageInformational errors
	ErrInfoMessageLengthTooLong = errors.New("info message length is longer than buffer")
	ErrFailedToReadMessage      = errors.New("failed to read message")
	ErrTooManyBytesInAlert      = errors.New("too many bytes in alert message")

	// AlertMessageInvalidateBlock errors
	ErrInvalidateBlockTooShort      = errors.New("invalidate block alert is less than 32 bytes")
	ErrFailedToReadBlockHash        = errors.New("failed to read block hash")
	ErrNoReasonMessageProvided      = errors.New("no reason message provided")
	ErrFailedToReadReasonInvalidate = errors.New("failed to read reason")

	// AlertMessageSetKeys errors
	ErrSetKeysAlertInvalidLength = errors.New("alert is not 165 bytes long")
	ErrFailedToReadPubKey        = errors.New("failed to read pubKey")
	ErrInvalidPubKeyFormat       = errors.New("invalid public key format")
	ErrSetKeysRPCError           = errors.New("set keys alert RPC response returned an error")

	// AlertMessageUnbanPeer errors
	ErrFailedToReadPeerUnban   = errors.New("failed to read peer")
	ErrFailedToReadReasonUnban = errors.New("failed to read reason")

	// AlertMessageUnfreezeUtxo errors
	ErrUnfreezeAlertTooShort      = errors.New("unfreeze alert is less than 57 bytes")
	ErrUnfreezeAlertInvalidLength = errors.New("unfreeze alert is not a multiple of 57 bytes")
	ErrUnfreezeAlertRPCError      = errors.New("unfreeze alert RPC response returned an error")

	// Overflow errors
	ErrEnforceAtHeightOverflow = errors.New("enforce at height exceeds maximum value")
	ErrValueExceedsMaxInt      = errors.New("value exceeds maximum int size")

	// Not found errors
	ErrAlertNotFound       = errors.New("alert not found")
	ErrLatestAlertNotFound = errors.New("latest alert not found")
)
