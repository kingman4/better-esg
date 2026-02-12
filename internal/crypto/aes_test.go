package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return key
}

func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	key := testKey(t)
	plaintext := "fda-temp-password-12345"

	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if encrypted == plaintext {
		t.Error("encrypted text should differ from plaintext")
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	key := testKey(t)

	encrypted, err := Encrypt("", key)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}

	if decrypted != "" {
		t.Errorf("expected empty string, got %q", decrypted)
	}
}

func TestEncrypt_UniqueNonces(t *testing.T) {
	key := testKey(t)
	plaintext := "same-input"

	enc1, _ := Encrypt(plaintext, key)
	enc2, _ := Encrypt(plaintext, key)

	if enc1 == enc2 {
		t.Error("two encryptions of the same plaintext should produce different ciphertexts (unique nonces)")
	}

	// Both should decrypt to the same value
	dec1, _ := Decrypt(enc1, key)
	dec2, _ := Decrypt(enc2, key)
	if dec1 != dec2 || dec1 != plaintext {
		t.Errorf("both should decrypt to %q, got %q and %q", plaintext, dec1, dec2)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	encrypted, _ := Encrypt("secret", key1)

	_, err := Decrypt(encrypted, key2)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := testKey(t)

	encrypted, _ := Encrypt("secret", key)

	// Decode, flip a byte, re-encode
	data, _ := base64.StdEncoding.DecodeString(encrypted)
	data[len(data)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(data)

	_, err := Decrypt(tampered, key)
	if err == nil {
		t.Error("expected error decrypting tampered ciphertext")
	}
}

func TestEncrypt_InvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16)

	_, err := Encrypt("test", shortKey)
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}

func TestDecrypt_InvalidKeyLength(t *testing.T) {
	_, err := Decrypt("dGVzdA==", make([]byte, 24))
	if err == nil {
		t.Error("expected error for 24-byte key")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key := testKey(t)

	_, err := Decrypt("not-valid-base64!!!", key)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key := testKey(t)

	// Just a few bytes — shorter than nonce size
	short := base64.StdEncoding.EncodeToString([]byte("ab"))

	_, err := Decrypt(short, key)
	if err == nil {
		t.Error("expected error for ciphertext shorter than nonce")
	}
}
