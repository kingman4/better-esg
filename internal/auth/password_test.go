package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	password := "correct-horse-battery"
	hash, err := HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)

	err = CheckPassword(password, hash)
	assert.NoError(t, err)
}

func TestCheckPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("real-password")
	require.NoError(t, err)

	err = CheckPassword("wrong-password", hash)
	assert.Error(t, err)
}

func TestHashPassword_DifferentHashesEachTime(t *testing.T) {
	h1, err := HashPassword("same-password")
	require.NoError(t, err)
	h2, err := HashPassword("same-password")
	require.NoError(t, err)

	assert.NotEqual(t, h1, h2, "bcrypt should produce different hashes due to salt")
}
