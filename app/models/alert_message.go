package models

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/bitcoinsv/bsvutil"
	"github.com/bsv-blockchain/go-bt/v2/chainhash"
	"github.com/mrz1836/go-datastore"

	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/utils"
)

const (
	// SignatureLength is the byte length of a single compact signature
	SignatureLength = 65

	// RequiredSignatures is the number of signatures from distinct active keys an alert must carry
	RequiredSignatures = 3
)

// AlertMessage is an object representing an alert message
type AlertMessage struct {
	// Base model
	model.Model `bson:",inline"`

	// Model specific fields
	ID             uint64 `json:"id" toml:"id" yaml:"id" bson:"_id" gorm:"primaryKey;comment:This is a unique identifier"`
	Hash           string `json:"hash" toml:"hash" yaml:"hash" bson:"hash" gorm:"<-;type:char(64);index;comment:This is the hash"`
	SequenceNumber uint32 `json:"sequence_number" toml:"sequence_number" yaml:"sequence_number" bson:"sequence_number" gorm:"<-;type:int8;index;comment:This is the alert sequence number"`
	Raw            string `json:"raw" toml:"raw" yaml:"raw" bson:"raw" gorm:"<-;type:text;comment:This is the raw alert message"`
	Processed      bool   `json:"processed" toml:"processed" yaml:"processed" bson:"processed" gorm:"<-;type:boolean;comment:This determine if the alert was processed"`

	// Private fields (never to be exported)
	alertType  AlertType
	data       []byte
	message    []byte
	signatures [][]byte
	timestamp  uint64
	version    uint32
}

// AlertMessageInterface is the interface for alert messages
type AlertMessageInterface interface {
	Read(msg []byte) error
	Do(ctx context.Context) error
	ToJSON(ctx context.Context) []byte
	MessageString() string
}

// NewAlertMessage creates a new alert message
func NewAlertMessage(opts ...model.Options) *AlertMessage {
	return &AlertMessage{
		Model: *model.NewBaseModel(model.NameAlertMessage, opts...),
	}
}

// NewAlertFromBytes creates a new alert from bytes
func NewAlertFromBytes(ak []byte, opts ...model.Options) (*AlertMessage, error) {
	opts = append(opts, model.New())
	newAlert := NewAlertMessage(opts...)
	newAlert.SetRawMessage(ak)
	err := newAlert.ReadRaw()
	if err != nil {
		return nil, err
	}

	// Return alert
	return newAlert, nil
}

// Name will get the name of the model
func (m *AlertMessage) Name() string {
	return model.NameAlertMessage.String()
}

// GetTableName will get the database table name of the model
func (m *AlertMessage) GetTableName() string {
	return model.TableAlertMessages
}

// GetID will get the model ID
func (m *AlertMessage) GetID() uint64 {
	return m.ID
}

// Display filter the model for display
func (m *AlertMessage) Display() interface{} {
	return m
}

// Migrate will run model-specific migrations on startup
func (m *AlertMessage) Migrate(client datastore.ClientInterface) error {
	return client.IndexMetadata(client.GetTableName(model.TableAlertMessages), model.MetadataField)
}

// BeginSaveWithTx will start saving the model into the Datastore with the provided transaction
func (m *AlertMessage) BeginSaveWithTx(ctx context.Context, tx *datastore.Transaction) ([]model.BaseInterface, error) {
	return model.BeginSaveWithTx(ctx, tx, m)
}

// Save will save the model into the Datastore
func (m *AlertMessage) Save(ctx context.Context) error {
	return model.Save(ctx, m)
}

// SetAlertType will set the alert type
func (m *AlertMessage) SetAlertType(t AlertType) {
	m.alertType = t
}

// GetAlertType will get the alert type
func (m *AlertMessage) GetAlertType() AlertType {
	return m.alertType
}

// SetRawMessage will set the alert raw message
func (m *AlertMessage) SetRawMessage(msg []byte) {
	m.message = msg
}

// GetRawMessage will get the raw message
func (m *AlertMessage) GetRawMessage() []byte {
	return m.message
}

// GetRawData will get the raw data
func (m *AlertMessage) GetRawData() []byte {
	return m.data
}

// SerializeData serializes the data
func (m *AlertMessage) SerializeData() {
	var ret []byte
	ret = binary.LittleEndian.AppendUint32(ret, m.version)
	ret = binary.LittleEndian.AppendUint32(ret, m.SequenceNumber)
	ret = binary.LittleEndian.AppendUint64(ret, m.timestamp)
	ret = binary.LittleEndian.AppendUint32(ret, uint32(m.alertType))
	ret = append(ret, m.message...)
	m.data = ret
	m.Hash = chainhash.DoubleHashH(m.data).String()
}

// Serialize serializes the alert
func (m *AlertMessage) Serialize() []byte {
	m.SerializeData()
	data := m.data
	for _, sig := range m.signatures {
		data = append(data, sig...)
	}
	m.Raw = hex.EncodeToString(data)
	return data
}

// SetSignatures sets the signatures on the alert
func (m *AlertMessage) SetSignatures(sigs [][]byte) {
	m.signatures = sigs
}

// AreSignaturesValid checks that the alert carries at least RequiredSignatures valid
// signatures over the alert data, each produced by a different active public key.
// A signature that does not verify against any active key, or a key that signs more
// than once, invalidates the alert.
func (m *AlertMessage) AreSignaturesValid(ctx context.Context) (bool, error) {
	keys, err := GetActivePublicKey(ctx, nil, model.WithAllDependencies(m.Config()))
	if err != nil {
		return false, err
	} else if len(keys) == 0 {
		return false, ErrNoActivePublicKeys
	}

	// Require the full signature set up front (an empty set must never validate)
	if len(m.signatures) < RequiredSignatures {
		m.Config().Services.Log.Debugf(
			"alert has %d signatures, %d required", len(m.signatures), RequiredSignatures,
		)
		return false, nil
	}

	// Resolve every active key to its address once. Signers are identified by address
	// rather than by the stored string, so the same key stored under two spellings is one signer.
	var keyByAddress map[string]string
	if keyByAddress, err = activeKeyAddresses(keys); err != nil {
		return false, err
	}

	// Each signature must come from an active key that has not already signed
	dataHex := hex.EncodeToString(m.data)
	usedAddresses := make(map[string]struct{}, len(m.signatures))
	for _, sig := range m.signatures {
		signer, ok := signerAddress(sig, dataHex)
		if !ok {
			m.Config().Services.Log.Debugf("signature %x is not a well formed compact signature", sig)
			return false, nil
		}
		if _, active := keyByAddress[signer]; !active {
			m.Config().Services.Log.Debugf("signature %x does not match any active key", sig)
			return false, nil
		}
		if _, used := usedAddresses[signer]; used {
			m.Config().Services.Log.Debugf("key %s signed the alert more than once", keyByAddress[signer])
			return false, nil
		}
		usedAddresses[signer] = struct{}{}
	}

	return true, nil
}

// Execute reads the alert payload and performs its action. It returns
// ErrUnknownAlertType when this build has no handler for the alert type.
func (m *AlertMessage) Execute(ctx context.Context) error {
	ak := m.ProcessAlertMessage()
	if ak == nil {
		return fmt.Errorf("%w: %d", ErrUnknownAlertType, m.alertType)
	}
	if err := ak.Read(m.GetRawMessage()); err != nil {
		return err
	}
	return ak.Do(ctx)
}

// activeKeyAddresses maps the address of every active key to the stored key string
func activeKeyAddresses(keys []*PublicKey) (map[string]string, error) {
	keyByAddress := make(map[string]string, len(keys))
	for _, key := range keys {
		pub, err := bitcoin.PubKeyFromString(key.Key)
		if err != nil {
			return nil, err
		}

		var addr *bsvutil.LegacyAddressPubKeyHash
		if addr, err = bitcoin.GetAddressFromPubKey(pub, true); err != nil {
			return nil, err
		} else if addr == nil {
			return nil, ErrFailedToConvertPubKey
		}
		if _, exists := keyByAddress[addr.String()]; !exists {
			keyByAddress[addr.String()] = key.Key
		}
	}
	return keyByAddress, nil
}

// signerAddress recovers the address of the key that produced sig over dataHex.
// The signature is range checked before recovery is attempted, because
// bsvec.RecoverCompact dereferences a nil pointer for some malformed inputs.
func signerAddress(sig []byte, dataHex string) (string, bool) {
	if !isValidCompactSignature(sig) {
		return "", false
	}
	pub, compressed, err := bitcoin.PubKeyFromSignature(base64.StdEncoding.EncodeToString(sig), dataHex)
	if err != nil {
		return "", false
	}
	addr, err := bitcoin.GetAddressFromPubKey(pub, compressed)
	if err != nil || addr == nil {
		return "", false
	}
	return addr.String(), true
}

// isValidCompactSignature reports whether sig is a well formed compact signature: exactly
// SignatureLength bytes, a header byte in the Bitcoin signed message range (27 to 34)
// and R and S each in [1, n-1]. bsvec.RecoverCompact does not range check R and S itself
// and dereferences a nil pointer when R is a multiple of the curve order (which is a valid
// x coordinate on secp256k1), so this must run before any recovery is attempted.
func isValidCompactSignature(sig []byte) bool {
	if len(sig) != SignatureLength || sig[0] < 27 || sig[0] > 34 {
		return false
	}
	n := bsvec.S256().N
	r := new(big.Int).SetBytes(sig[1:33])
	s := new(big.Int).SetBytes(sig[33:])
	return r.Sign() > 0 && r.Cmp(n) < 0 && s.Sign() > 0 && s.Cmp(n) < 0
}

// ProcessAlertMessage processes the alert message and converts to an alert message interface
func (m *AlertMessage) ProcessAlertMessage() AlertMessageInterface {
	switch m.alertType {
	case AlertTypeInformational:
		return &AlertMessageInformational{
			AlertMessage: *m,
		}
	case AlertTypeFreezeUtxo:
		return &AlertMessageFreezeUtxo{
			AlertMessage: *m,
		}
	case AlertTypeUnfreezeUtxo:
		return &AlertMessageUnfreezeUtxo{
			AlertMessage: *m,
		}
	case AlertTypeConfiscateUtxo:
		return &AlertMessageConfiscateTransaction{
			AlertMessage: *m,
		}
	case AlertTypeBanPeer:
		return &AlertMessageBanPeer{
			AlertMessage: *m,
		}
	case AlertTypeUnbanPeer:
		return &AlertMessageUnbanPeer{
			AlertMessage: *m,
		}
	case AlertTypeInvalidateBlock:
		return &AlertMessageInvalidateBlock{
			AlertMessage: *m,
		}
	case AlertTypeSetKeys:
		return &AlertMessageSetKeys{
			AlertMessage: *m,
			Hash:         m.Hash,
		}
	default:
		return nil
	}
}

// SetVersion sets the version of the message
func (m *AlertMessage) SetVersion(ver uint32) {
	m.version = ver
}

// Version returns the version of the message
func (m *AlertMessage) Version() uint32 {
	return m.version
}

// SetTimestamp sets the timestamp of the message
func (m *AlertMessage) SetTimestamp(ts uint64) {
	m.timestamp = ts
}

// Timestamp returns the timestamp of the message
func (m *AlertMessage) Timestamp() uint64 {
	return m.timestamp
}

// ReadRaw sets the model fields based on the raw message
func (m *AlertMessage) ReadRaw() error {
	if len(m.GetRawMessage()) == 0 {
		ak, err := hex.DecodeString(m.Raw)
		if err != nil {
			return err
		}
		m.SetRawMessage(ak)
	}

	if len(m.GetRawMessage()) < 20 {
		// Minimum length: version(4) + sequence(4) + timestamp(8) + alertType(4) = 20 bytes
		return ErrAlertTooShort
	}
	ak := m.GetRawMessage()
	version := binary.LittleEndian.Uint32(ak[:4])
	sequenceNumber := binary.LittleEndian.Uint32(ak[4:8])
	timestamp := binary.LittleEndian.Uint64(ak[8:16])
	alertType := binary.LittleEndian.Uint32(ak[16:20])

	alertAndSignature := ak[20:]

	// Every alert type carries exactly RequiredSignatures compact signatures
	sigLen := RequiredSignatures * SignatureLength

	// This is the minimum length this data should be. Signature byte length + 2 bytes
	// This would imply an informational alert with a message 1 byte long... not practical
	// but possible. Regardless, let's just error out now if this length is lower. At least
	// allows us to grab the expected signature.
	if len(alertAndSignature) < sigLen+2 {
		return ErrAlertMessageInvalidLength
	}

	// Get alert message bytes
	alert := alertAndSignature[:len(alertAndSignature)-sigLen]

	// Get signature bytes
	signatures := alertAndSignature[len(alertAndSignature)-sigLen:]
	sigs := make([][]byte, 0, RequiredSignatures)

	// Loop through all signatures and create an array
	for i := 0; i < RequiredSignatures; i++ {
		sigs = append(sigs, signatures[:SignatureLength])
		signatures = signatures[SignatureLength:]
	}

	dataLen := 20 + len(alert)

	m.SetAlertType(AlertType(alertType))
	m.message = alert
	m.SequenceNumber = sequenceNumber
	m.timestamp = timestamp
	m.version = version
	m.data = ak[:dataLen]
	m.signatures = sigs
	_ = m.Serialize()
	return nil
}

// GetAlertMessageBySequenceNumber will get the model with the given conditions
func GetAlertMessageBySequenceNumber(ctx context.Context, sequenceNumber uint32, opts ...model.Options) (*AlertMessage, error) {
	// Get the record
	message := NewAlertMessage(opts...)
	message.SequenceNumber = sequenceNumber
	conditions := make(map[string]interface{})
	conditions["sequence_number"] = sequenceNumber
	if err := model.Get(
		ctx, message, conditions, model.DefaultDatabaseReadTimeout, true, // In-case an update is occurring
	); err != nil {
		if errors.Is(err, datastore.ErrNoResults) {
			return nil, ErrAlertNotFound
		}
		return nil, err
	}

	return message, nil
}

// GetLatestAlert will get the model with the given conditions
func GetLatestAlert(ctx context.Context, metadata *model.Metadata, opts ...model.Options) (*AlertMessage, error) {
	// Set the conditions
	conditions := &map[string]interface{}{
		utils.FieldDeletedAt: map[string]interface{}{ // IS NULL
			utils.ExistsCondition: false,
		},
	}

	// Set the query params
	queryParams := &datastore.QueryParams{
		Page:          1,
		PageSize:      1,
		OrderByField:  utils.FieldSequenceNumber,
		SortDirection: utils.SortDescending,
	}

	// Get the record
	modelItems := make([]*AlertMessage, 0)
	if err := model.GetModelsByConditions(
		ctx, model.NameAlertMessage, &modelItems, metadata, conditions, queryParams, opts...,
	); err != nil {
		return nil, err
	} else if len(modelItems) == 0 {
		return nil, ErrLatestAlertNotFound
	}

	// Return the first item (only item)
	return modelItems[0], nil
}

// GetAllAlerts returns all alerts in the database
func GetAllAlerts(ctx context.Context, metadata *model.Metadata, opts ...model.Options) ([]*AlertMessage, error) {
	// Set the conditions
	conditions := &map[string]interface{}{
		utils.FieldDeletedAt: map[string]interface{}{ // IS NULL
			utils.ExistsCondition: false,
		},
	}

	// Set the query params
	queryParams := &datastore.QueryParams{
		OrderByField:  utils.FieldSequenceNumber,
		SortDirection: utils.SortAscending,
	}

	// Get the record
	modelItems := make([]*AlertMessage, 0)
	if err := model.GetModelsByConditions(
		ctx, model.NameAlertMessage, &modelItems, metadata, conditions, queryParams, opts...,
	); err != nil {
		return nil, err
	} else if len(modelItems) == 0 {
		return nil, nil
	}

	// Return the first item (only item)
	return modelItems, nil
}

// GetAllUnprocessedAlerts will get all alerts that weren't successfully processed
func GetAllUnprocessedAlerts(ctx context.Context, metadata *model.Metadata, opts ...model.Options) ([]*AlertMessage, error) {
	// Set the conditions
	conditions := &map[string]interface{}{
		utils.FieldDeletedAt: map[string]interface{}{ // IS NULL
			utils.ExistsCondition: false,
		},
		"processed": false,
	}

	// Set the query params
	queryParams := &datastore.QueryParams{
		OrderByField:  utils.FieldSequenceNumber,
		SortDirection: utils.SortAscending,
	}

	// Get the record
	modelItems := make([]*AlertMessage, 0)
	if err := model.GetModelsByConditions(
		ctx, model.NameAlertMessage, &modelItems, metadata, conditions, queryParams, opts...,
	); err != nil {
		return nil, err
	} else if len(modelItems) == 0 {
		return nil, nil
	}

	// Return the first item (only item)
	return modelItems, nil
}
