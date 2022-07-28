package bbgo

import (
	"bytes"
	"fmt"
	"image/png"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"

	"github.com/c9s/bbgo/pkg/service"
)

func writeOTPKeyAsQRCodePNG(key *otp.Key, imagePath string) error {
	// Convert TOTP key into a PNG
	var buf bytes.Buffer
	img, err := key.Image(512, 512)
	if err != nil {
		return err
	}

	if err := png.Encode(&buf, img); err != nil {
		return err
	}

	if err := ioutil.WriteFile(imagePath, buf.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

// setupNewOTPKey generates a new otp key and save the secret as a qrcode image
func setupNewOTPKey(qrcodeImagePath string) (*otp.Key, error) {
	key, err := service.NewDefaultTotpKey()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to setup totp (time-based one time password) key")
	}

	printOtpKey(key)

	if err := writeOTPKeyAsQRCodePNG(key, qrcodeImagePath); err != nil {
		return nil, err
	}

	return key, nil
}

func printOtpKey(key *otp.Key) {
	fmt.Println("")
	fmt.Println("====================================================================")
	fmt.Println("               PLEASE STORE YOUR OTP KEY SAFELY                     ")
	fmt.Println("====================================================================")
	fmt.Printf("  Issuer:       %s\n", key.Issuer())
	fmt.Printf("  AccountName:  %s\n", key.AccountName())
	fmt.Printf("  Secret:       %s\n", key.Secret())
	fmt.Printf("  Key URL:      %s\n", key.URL())
	fmt.Println("====================================================================")
	fmt.Println("")
}

func printOtpAuthGuide(qrcodeImagePath string) {
	fmt.Printf(`
To scan your OTP QR code, please run the following command:
	
	open %s

For telegram, send the auth command with the generated one-time password to the bbo bot you created to enable the notification:

	/auth

`, qrcodeImagePath)
}

