package sanative

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/nigel447/sanative/util"
)

// GeneratePassCode Generates Passcode using a UTF-8 (not base32) secret and custom paramters
func GeneratePassCode(secret string) string {

	passcode, err := totp.GenerateCodeCustom(secret, time.Unix(30, 0).UTC(), totp.ValidateOpts{

		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA512,
	})

	if err != nil {
		panic(err)
	}
	return passcode
}

// ValidateCode to do
func ValidateCode(code string, secret string) bool {

	ret := totp.Validate(code, secret)

	return ret
}

// ValidateCodeSHA256 to do
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

// ValidateCodeSHA512 to do
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
