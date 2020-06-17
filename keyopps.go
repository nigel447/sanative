/** MIT License

Copyright (c) 2015 - present

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package sanative

import (
	"crypto/ecdsa"
	"encoding/hex"

	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	snEcies "github.com/nigel447/sanative/ecies"
	snUtil "github.com/nigel447/sanative/util"
)

func NewEntityID(key *ecies.PrivateKey) *snUtil.EntityID {
	// first obtain ecdsa key for signing
	ecdsaKey := key.ExportECDSA()
	// obtain signature and attributes to verify
	sig, khash, publicKey, err := snEcies.EthSignIdentityKey(ecdsaKey)
	if err != nil {
		snUtil.LogError("EthSignIdentityKey error:", err)
	}

	return &snUtil.EntityID{Signature: sig, Keccakhash: khash, PublicKey: publicKey}

}

// EthExportKeyAsGoArtifact used to set up static hex key
func EthExportKeyAsGoArtifact(key *ecdsa.PrivateKey) string {

	k := hex.EncodeToString(ethCrypto.FromECDSA(key))
	return k

}

// HexKey hex encoded key to ECIS key
func HexKey(prv string) *ecies.PrivateKey {
	key, err := ethCrypto.HexToECDSA(prv)
	if err != nil {
		panic(err)
	}
	return ecies.ImportECDSA(key)
}
