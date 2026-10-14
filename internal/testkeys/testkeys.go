// Package testkeys holds the private keys behind the local and test genesis keys.
//
// These keys are public, so they must never sign anything a real node trusts. Only
// test code imports this package, which keeps the keys out of the shipped binaries.
package testkeys

import "github.com/bsv-blockchain/go-alert-system/utils"

// Private keys for the local and test genesis keys
const (
	Key1 = "e785e99372b5ecc65828d120ad7d7c4f8ce7b3496833ad0143cff7eff90dc822"
	Key2 = "7445f20674fe5e051ac5b6712ad250760686cd9a38676d3f92e165380708903e"
	Key3 = "4e7d00a25e93a5736f294a2867b3ec73a8e7bdd88ea35e390c203d52684e5292"
	Key4 = "0f5491fd840b47293ee85a4068b05249ba66958185ca1626442c472ef16cc2aa"
	Key5 = "161a9d680f1952fef2f2572bfae30e7eda047908a180cbb00a16a4ee270abf62"
)

// SignWithGenesis will sign the data with three of the local and test genesis keys
func SignWithGenesis(data []byte) ([][]byte, error) {
	return utils.SignWithKeys(data, []string{Key1, Key2, Key3})
}
