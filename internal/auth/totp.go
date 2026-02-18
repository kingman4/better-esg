package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	totpIssuer        = "FDA ESG NextGen"
	backupCodeLength  = 8
	backupCodeCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars (0/O, 1/I)
	backupBcryptCost  = 10                                 // lower than password since codes are random
)

// GenerateTOTP creates a new TOTP key for the given email address.
// Returns the key which contains the secret and the otpauth:// URL for QR codes.
func GenerateTOTP(email string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: email,
	})
	if err != nil {
		return nil, fmt.Errorf("generating TOTP key: %w", err)
	}
	return key, nil
}

// ValidateTOTP checks a 6-digit TOTP code against the given secret.
func ValidateTOTP(code, secret string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes creates count random alphanumeric backup codes.
func GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := randomString(backupCodeLength, backupCodeCharset)
		if err != nil {
			return nil, fmt.Errorf("generating backup code: %w", err)
		}
		codes[i] = code
	}
	return codes, nil
}

// HashBackupCode returns a bcrypt hash of a backup code.
func HashBackupCode(code string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(code), backupBcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing backup code: %w", err)
	}
	return string(hash), nil
}

// CheckBackupCode compares a plaintext backup code against a bcrypt hash.
// Returns true on match.
func CheckBackupCode(code, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil
}

// randomString generates a cryptographically random string of the given length
// using characters from the provided charset.
func randomString(length int, charset string) (string, error) {
	result := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := range result {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}
