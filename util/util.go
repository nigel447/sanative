/** MIT License

Copyright (c) 2015

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
package util

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"io/ioutil"
	"net/url"
)

func Endpoint(isTest bool, pathPart string) string {

	if isTest {
		endpoint := url.URL{
			Scheme: "http",
			Host:   "localhost:8080",
			Path:   pathPart,
		}
		return endpoint.String()
	}
	return "endpoint"
}

func (eid *EntityID) NewSession() *Session {
	return &Session{Eid: eid, IsValid: true, Nonce: hex.EncodeToString(eid.Keccakhash)}
}

func (eid *EntityID) NewMessageSession() *MessageSession {
	return &MessageSession{
		PublicKey: hex.EncodeToString(eid.PublicKey),
		IsValid:   true,
		Nonce:     hex.EncodeToString(eid.Keccakhash)}
}

func ECDSASignatureKeyPair(key ecdsa.PrivateKey) ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(key.D.Bytes())))
	hex.Encode(dst, key.D.Bytes())
	priKey, err := ethCrypto.HexToECDSA(string(dst))
	if err != nil {
		LogError("ECDSASignatureKeyPair HexToECDSA error:", err)
		return nil, err
	}
	var ptr *ecdsa.PublicKey = &priKey.PublicKey
	publicKeyBytes := ethCrypto.FromECDSAPub(ptr)

	return publicKeyBytes, nil

}

func ECDSAPrivateKeyAsHex(key ecies.PrivateKey) []byte {
	dst := make([]byte, hex.EncodedLen(len(key.D.Bytes())))
	hex.Encode(dst, key.D.Bytes())
	return dst
}

// loging
func LogError(msg string, err error) {
	if err != nil {
		fmt.Println(msg+" %v", err)
	}

}

func LogECIESKeyHex(msg string, key ecies.PrivateKey) {

	dst := make([]byte, hex.EncodedLen(len(key.D.Bytes())))
	hex.Encode(dst, key.D.Bytes())
	fmt.Printf(msg+" %s\n", dst)
}

func LogBinDataHex(msg string, data []byte) {
	dst := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(dst, data)
	fmt.Printf(msg+" %s\n", dst[:])

}

func LogBinData(msg string, data []byte) {

	fmt.Printf(msg+" %s\n", string(data))

}

func LogStringData(msg string, data string) {

	fmt.Printf(msg+" %s\n", data)

}

func ReadFileKey(file string) string {
	keyBytes, err := ioutil.ReadFile(file)
	if err != nil {
		LogError("ReadFileKey error:", err)

	}
	return string(keyBytes)
}

// func GenerateNonceURLSafe() (string, error) {
// 	b, err := generateNonceBytes()
// 	return base64.URLEncoding.EncodeToString(b), err
// }

func GenerateNonceBytes() [32]byte {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		LogError("ReadFileKey error:", err)
	}
	var ret [32]byte
	copy(ret[:], b)
	return ret
}
