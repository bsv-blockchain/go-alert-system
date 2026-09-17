package p2p

import "errors"

// Errors for the p2p package
var (
	ErrAlertNotFoundBySequence  = errors.New("failed to find alert by sequence in datastore")
	ErrAlertNotLatest           = errors.New("failed to find latest alert datastore")
	ErrInvalidAlerts            = errors.New("peer is sending invalid alerts")
	ErrSyncFiveBytes            = errors.New("sync message is less than 5 bytes, not valid")
	ErrSyncMessageByte          = errors.New("sync message needs at least a byte")
	ErrSyncMessageTooLarge      = errors.New("sync frame exceeds the maximum allowed size")
	ErrSyncPanic                = errors.New("recovered from panic while processing sync message")
	ErrSyncTimeout              = errors.New("sync from peer process timed out")
	ErrUnexpectedSequenceNumber = errors.New("peer sent an alert with an unexpected sequence number")
	ErrUnknownSyncMessageType   = errors.New("peer sent an unknown sync message type")
	ErrPriorAlertMissing        = errors.New("alert preceding this sequence number is not stored")
	ErrDuplicateAlert           = errors.New("alert with this sequence number is already stored")
)
