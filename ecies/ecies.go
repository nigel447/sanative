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
package ecies

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/nigel447/sanative/util"
)

// GenerateECKey returns a ecies public/private elliptic curve key pair.
func GenerateECKey() *ecies.PrivateKey {
	prv, err := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)

	if err != nil {
		util.LogError("GenerateECKey error:", err)
		return nil
	}

	return prv

}

// EciesEncrypt returns a cypher text as a byte array.
func EciesEncrypt(data []byte, key ecies.PrivateKey) ([]byte, error) {

	ret, err := ecies.Encrypt(rand.Reader, &key.PublicKey, data, nil, nil)

	if err != nil {
		util.LogError("GenerateECKey error:", err)
		return nil, err
	}

	return ret, nil
}

// EciesEncrypt returns the plain text as a byte array.
func EciesDecrypt(data []byte, key ecies.PrivateKey) ([]byte, error) {

	ret, err := ecies.Encrypt(rand.Reader, &key.PublicKey, data, nil, nil)

	if err != nil {
		util.LogError("EciesDecrypt error:", err)
		return nil, err
	}

	return ret, nil
}

// EthVerify verifys signature using eth code kekack hash ect ...
func EthVerify(pubKey []byte, hash []byte, sig []byte) bool {
	signatureNoRecoverID := sig[:len(sig)-1]
	return crypto.VerifySignature(pubKey, hash, signatureNoRecoverID)
}

//EthSignIdentityKey  generates signature using eth code kekack hash ect ...
func EthSignIdentityKey(key *ecdsa.PrivateKey) (sig []byte, khash []byte, pubKey []byte, err error) {
	publicKeyBytes, err := util.ECDSASignatureKeyPair(*key)
	if err != nil {
		util.LogError("ECDSASignatureKeyPair error:", err)
		return nil, nil, nil, err
	}
	hash := crypto.Keccak256Hash(publicKeyBytes)
	// remove 0x
	cleanHash := hash[0:len(hash.Bytes())]
	sig, errs := crypto.Sign(cleanHash, key)
	return sig, cleanHash, publicKeyBytes, errs
}
