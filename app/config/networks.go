package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Network identifies a public alert network: the genesis keys that may sign
// alerts, and the libp2p protocol and pubsub topic the alerts travel on
type Network struct {
	GenesisKeys []string
	ProtocolID  string
	TopicName   string
}

// networkFile is the subset of an embedded environment config that identifies the alert network
type networkFile struct {
	GenesisKeys []string `json:"genesis_keys"`
	P2P         struct {
		AlertSystemProtocolID string `json:"alert_system_protocol_id"`
		TopicName             string `json:"topic_name"`
	} `json:"p2p"`
}

// NetworkDefaults returns the genesis keys, protocol ID and topic name of the
// embedded config for environment (e.g. EnvironmentMainnet, EnvironmentTestnet,
// EnvironmentStn). Unlike LoadConfigFile, it reads no environment variables and
// touches no global state, so it is safe for applications that embed the alert
// system and need the network defaults without loading a full config.
func NetworkDefaults(environment string) (Network, error) {
	environment = strings.ToLower(environment)
	if !isValidEnvironment(environment) {
		return Network{}, fmt.Errorf("%w: %q", ErrInvalidEnvironment, environment)
	}

	b, err := envDir.ReadFile("envs/" + environment + ".json")
	if err != nil {
		return Network{}, err
	}

	var f networkFile
	if err = json.Unmarshal(b, &f); err != nil {
		return Network{}, fmt.Errorf("error parsing %s config: %w", environment, err)
	}

	return Network{
		GenesisKeys: f.GenesisKeys,
		ProtocolID:  f.P2P.AlertSystemProtocolID,
		TopicName:   f.P2P.TopicName,
	}, nil
}
