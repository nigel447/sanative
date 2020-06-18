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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"strconv"
	"testing"

	snEcies "github.com/nigel447/sanative/ecies"
	snUtil "github.com/nigel447/sanative/util"
)

const ()

var (
	message = []byte("A long string of text for testing encrypt avoiding the existensial crisis stuff for now")

	SerTestData = []byte(`{
		"Keccakhash":"c63a6dc8aafed8a7deee66c7dc64cd3804cd9d5cece26f24ce1c7a330d12237c",
		"PublicKey":"044465b2b529618c56f5741e1bcb3eb553ce5d7a5f75345f03b39e79c8498354561c0b7f30bc99d4396ba912fcccef7ca2a4ee43ea79336e4d61cbb24c710538b6",
		"Signature":"1d7ba6c0525de15a3e15f490471b5057e7a0a637cab482286a9f7a5454c9d12c63ebf73bfd656a31e610ecf041dabdcb489f791b19d145e46e193b6994f1427601"
		}`)

	secSha512T = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))
)

func TestKeyOpps(t *testing.T) {

	prv := genECIESKey()

	ecdsaKey := prv.ExportECDSA()

	ret2 := EthExportKeyAsGoArtifact(ecdsaKey)

	snUtil.LogStringData("ecies key as ecdsa key", ret2)

}

func TestExportStaticKey(t *testing.T) {

	prv := genECIESKey()

	ecdsaKey := prv.ExportECDSA()

	ret := EthExportKeyAsGoArtifact(ecdsaKey)

	snUtil.LogStringData("ret", ret)

}

func TestExportPublicKey(t *testing.T) {

	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))
	ecPubDsa := PrvECISHexKey.PublicKey.ExportECDSA()
	snUtil.LogBinDataHex("PrvECISHexKey PublicKey as dsa", ethCrypto.FromECDSAPub(ecPubDsa))
}

func TestSerEntityID(t *testing.T) {
	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))
	eid := NewEntityID(PrvECISHexKey)
	ret := eid.SerEntityIdToJson()
	snUtil.LogStringData("ser entity:", string(ret))

}

func TestSession(t *testing.T) {
	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))
	eid := NewEntityID(PrvECISHexKey)
	// session is a ptr here
	session := eid.NewSession()
	snUtil.LogStringData("session is valid", strconv.FormatBool(session.IsValid))
	// golang allows us to drop the ptr syntax here,
	snUtil.LogStringData("session nonce as hex", session.Nonce)
	sessions := make(map[string]snUtil.Session)
	sessions[session.Nonce] = *session
	sessionFromMap := sessions[session.Nonce]
	snUtil.LogStringData("session from map", sessionFromMap.Nonce)

	ret := session.SerSessionToJson()
	snUtil.LogStringData("ser session json:", string(ret))

	derSession := snUtil.DeJsonToSession(string(ret))
	snUtil.LogStringData("de ser Session nonce:", derSession.Nonce)

	mssgSession := eid.NewMessageSession()
	ret2 := mssgSession.SerMessageSessionToJson()
	snUtil.LogStringData("ser MessageSession:", string(ret2))

	derMssgSession := snUtil.DeJsonToMessageSession(string(ret2))
	snUtil.LogStringData("de ser derMssgSession nonce:", derMssgSession.Nonce)

}
func TestDeEntityID(t *testing.T) {
	SerEntityId := make(map[string]string)
	json.Unmarshal(SerTestData, &SerEntityId)
	deid := snUtil.DeJsonToEntityId(SerEntityId)
	snUtil.LogBinDataHex("TestDeEntityID PublicKey ", deid.PublicKey)

}

func TestEncryptStaticKey(t *testing.T) {

	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))
	ct, err := snEcies.EciesEncrypt(message, *PrvECISHexKey)

	if err != nil {
		snUtil.LogError("EciesEncrypt error:", err)
	}

	snUtil.LogBinDataHex("cypher text", ct)

	pt, err := PrvECISHexKey.Decrypt(ct, nil, nil)
	if err != nil {
		snUtil.LogError("Decrypt error:", err)
	}

	snUtil.LogBinData("plain text", pt)
}

func TestEthVerify(t *testing.T) {
	PrvECISHexKey := HexKey(snUtil.ReadFileKey("keyhex.txt"))

	ecdsaKey := PrvECISHexKey.ExportECDSA()

	//  publicKey,  err := util.ECDSASignatureKeyPair(*ecdsaKey)
	sig, khash, publicKey, err := snEcies.EthSignIdentityKey(ecdsaKey)
	if err != nil {
		snUtil.LogError("EthSignIdentityKey error:", err)
	}

	ret := snEcies.EthVerify(publicKey, khash, sig)
	snUtil.LogStringData("signature is valid", strconv.FormatBool(ret))
}

func genECIESKey() *ecies.PrivateKey {

	prv, err := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)

	if err != nil {
		snUtil.LogError("GenerateKey error:", err)
		return nil
	}

	return prv
}
