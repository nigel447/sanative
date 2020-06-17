package sanative

import (
	// "encoding/base32"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/nigel447/sanative/util"
)

// Generates Passcode using a UTF-8 (not base32) secret and custom paramters
func GeneratePassCode(secret string) string {

	passcode, err := totp.GenerateCodeCustom(secret, time.Unix(30, 0).UTC(), totp.ValidateOpts{

		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})

	// passcode, err := totp.GenerateCode(secret, time.Now())

	if err != nil {
		panic(err)
	}
	return passcode
}

func ValidateCode(code string, secret string) bool {

	ret := totp.Validate(code, secret)

	return ret
}

func ValidateCodeSHA256(code string, secret string) bool {

	valid, err := totp.ValidateCustom(code, secret,
		time.Unix(30, 0).UTC(),
		totp.ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA256,
		},
	)

	if err != nil {
		util.LogError("", err)
	}

	return valid
}

func ValidateCodeSHA512(code string, secret string) bool {

	valid, err := totp.ValidateCustom(code, secret,
		time.Unix(30, 0).UTC(),
		totp.ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA512,
			Skew:      1,
		},
	)

	if err != nil {
		util.LogError("", err)
	}

	return valid
}
