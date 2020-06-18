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
	"encoding/base32"
	snUtil "github.com/nigel447/sanative/util"
	"strconv"
	"testing"
)

const (
	keccakhash = "c63a6dc8aafed8a7deee66c7dc64cd3804cd9d5cece26f24ce1c7a330d12237c"
	twoFACode  = "12345678"
)

var (
	data = []byte("this is a test")
)

func TestMessageSerde(t *testing.T) {

	mssg := &snUtil.Message{Nonce: keccakhash, TwoFACode: twoFACode, Data: data}
	js := mssg.SerMessageToJson()
	snUtil.LogStringData("ser entity:", string(js))
}

func TestTwoFA(t *testing.T) {
	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))
	ecdsaKey := PrvECISHexKey.ExportECDSA()
	publicKeyBytes, err := snUtil.ECDSASignatureKeyPair(*ecdsaKey)
	snUtil.LogBinDataHex("publicKeyBytes as hex string", publicKeyBytes)
	if err != nil {
		snUtil.LogError("EthSignIdentityKey error:", err)
	}
	key := base32.StdEncoding.EncodeToString(publicKeyBytes)
	snUtil.LogStringData("2fa key as base32 secret", key)
	code := GeneratePassCode(key)
	snUtil.LogStringData("2fa code", code)
	ret2 := ValidateCodeSHA512(code, key)
	snUtil.LogStringData("2fa is valid", strconv.FormatBool(ret2))
}

func TestEndPoint(t *testing.T) {
	snUtil.LogStringData("ser entity:", snUtil.Endpoint(true, "session"))
}

func TestClientMesageFlow(t *testing.T) {
	// get a key for session config
	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))
	// create an entity id
	eid := NewEntityID(PrvECISHexKey)
	// create a session
	session := eid.NewSession()
	// sessions will be stored in a map with a nonce as key
	sessions := make(map[string]snUtil.Session)
	sessions[session.Nonce] = *session

	// now create a message session, for the client
	mssgSession := eid.NewMessageSession()

	// check nonce and key
	snUtil.LogStringData("mssgSession.Nonce", mssgSession.Nonce)
	snUtil.LogStringData("session.Nonce", session.Nonce)
	snUtil.LogStringData("mssgSession.PublicKey", mssgSession.PublicKey)

	// test 2fa code generate
	code := GeneratePassCode(mssgSession.PublicKey)
	snUtil.LogStringData("code", code)
	// test 2fa code verify
	ret2 := ValidateCodeSHA512(code, mssgSession.PublicKey)
	snUtil.LogStringData("2fa is valid", strconv.FormatBool(ret2))

}
