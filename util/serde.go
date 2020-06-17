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
package util

import (
	// "github.com/ethereum/go-ethereum/crypto/ecies"
	"encoding/hex"
	"encoding/json"
)

// EntityID to do
type EntityID struct {
	Signature  []byte
	Keccakhash []byte
	PublicKey  []byte
}

// Session to do
type Session struct {
	Nonce   string
	IsValid bool
	Eid     *EntityID
}

// MessageSession use, server sends to client config
type MessageSession struct {
	Nonce     string
	IsValid   bool
	PublicKey string
}

// Message to do
type Message struct {
	TwoFACode string
	Nonce     string
	Data      []byte
}

// JsonResponse to do
type JsonResponse struct {
	Message string
}

// JsonSessionResponse to do
type JsonSessionResponse struct {
	Message string
	Data    MessageSession
}


// SerMessageToJson to do
func (mssg *Message) SerMessageToJson() []byte {
	ret, err := json.Marshal(mssg)
	if err != nil {
		LogError("SerMessageToJson error:", err)
	}
	return ret

}
// SerSessionToJson to do
func (session *Session) SerSessionToJson() []byte {

	ret, err := json.Marshal(session)
	if err != nil {
		LogError("SerSessionToJson error:", err)
	}
	return ret

}

// SerMessageSessionToJson todo remove
func (messageSession *MessageSession) SerMessageSessionToJson() []byte {

	ret, err := json.Marshal(messageSession)
	if err != nil {
		LogError("SerSessionToJson error:", err)
	}
	return ret

}

// SerEntityIdToJson to do
func (eid *EntityID) SerEntityIdToJson() []byte {
	SerEntityId := make(map[string]string)
	SerEntityId["Signature"] = hex.EncodeToString(eid.Signature)
	SerEntityId["Keccakhash"] = hex.EncodeToString(eid.Keccakhash)
	SerEntityId["PublicKey"] = hex.EncodeToString(eid.PublicKey)
	ret, err := json.Marshal(SerEntityId)
	if err != nil {
		LogError("SerEntityIdToHex error:", err)
	}
	return ret

}

/*
{"Nonce":"c63a6dc8aafed8a7deee66c7dc64cd3804cd9d5cece26f24ce1c7a330d12237c",
"IsValid":true,
"Eid":{"Signature":"HXumwFJd4Vo+FfSQRxtQV+egpjfKtIIoap96VFTJ0Sxj6/c7/WVqMeYQ7PBB2r3LSJ95GxnRReRuGTtplPFCdgE=",
		"Keccakhash":"xjptyKr+2Kfe7mbH3GTNOATNnVzs4m8kzhx6Mw0SI3w=",
		"PublicKey":"BERlsrUpYYxW9XQeG8s+tVPOXXpfdTRfA7OeechJg1RWHAt/MLyZ1DlrqRL8zO98oqTuQ+p5M25NYcuyTHEFOLY="}}
*/
// DeJsonToSession to do
func DeJsonToSession(serJson string) *Session {

	session := &Session{}
	json.Unmarshal([]byte(serJson), session)
	return session

}

// DeJsonToMessageSession to do
func DeJsonToMessageSession(serJson string) *MessageSession {

	messageSession := &MessageSession{}
	json.Unmarshal([]byte(serJson), messageSession)
	return messageSession

}

// DeJsonToEntityId to do
func DeJsonToEntityId(serJson map[string]string) *EntityID {

	sig := serJson["Signature"]
	khash := serJson["Keccakhash"]
	pubKey := serJson["PublicKey"]

	derEntityID := &EntityID{}

	derSignature, err0 := hex.DecodeString(sig)
	if err0 != nil {

	}
	derEntityID.Signature = derSignature

	derKeccakhash, err1 := hex.DecodeString(khash)
	if err1 != nil {

	}
	derEntityID.Keccakhash = derKeccakhash

	derPublicKey, err2 := hex.DecodeString(pubKey)
	if err2 != nil {

	}
	derEntityID.PublicKey = derPublicKey

	return derEntityID
}
