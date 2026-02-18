package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTP(t *testing.T) {
	key, err := GenerateTOTP("test@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP failed: %v", err)
	}

	if key.Secret() == "" {
		t.Error("expected non-empty secret")
	}
	if key.Issuer() != "FDA ESG NextGen" {
		t.Errorf("expected issuer 'FDA ESG NextGen', got %q", key.Issuer())
	}
	if key.AccountName() != "test@example.com" {
		t.Errorf("expected account 'test@example.com', got %q", key.AccountName())
	}
}

func TestValidateTOTP_ValidCode(t *testing.T) {
	key, err := GenerateTOTP("test@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP failed: %v", err)
	}

	// Generate a valid code for the current time
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if !ValidateTOTP(code, key.Secret()) {
		t.Error("expected valid code to pass validation")
	}
}

func TestValidateTOTP_InvalidCode(t *testing.T) {
	key, err := GenerateTOTP("test@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTP failed: %v", err)
	}

	if ValidateTOTP("000000", key.Secret()) {
		t.Error("expected invalid code to fail validation")
	}
}

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes(10)
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}

	if len(codes) != 10 {
		t.Errorf("expected 10 codes, got %d", len(codes))
	}

	// All codes should be unique and the right length
	seen := map[string]bool{}
	for _, code := range codes {
		if len(code) != backupCodeLength {
			t.Errorf("expected code length %d, got %d for %q", backupCodeLength, len(code), code)
		}
		if seen[code] {
			t.Errorf("duplicate code: %q", code)
		}
		seen[code] = true
	}
}

func TestBackupCodeHashAndCheck(t *testing.T) {
	codes, err := GenerateBackupCodes(1)
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	code := codes[0]

	hash, err := HashBackupCode(code)
	if err != nil {
		t.Fatalf("HashBackupCode failed: %v", err)
	}

	if !CheckBackupCode(code, hash) {
		t.Error("expected correct code to match hash")
	}

	if CheckBackupCode("WRONGCODE", hash) {
		t.Error("expected wrong code to not match hash")
	}
}
