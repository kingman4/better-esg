package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-that-is-at-least-32-bytes-long!"

func TestSignAndVerifyAccessToken(t *testing.T) {
	token, err := SignAccessToken("user-1", "org-1", "admin", testSecret)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := VerifyToken(token, testSecret)
	require.NoError(t, err)

	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, "org-1", claims.OrgID)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, issuer, claims.Issuer)
	assert.Equal(t, "user-1", claims.Subject)
}

func TestSignAndVerifyRefreshToken(t *testing.T) {
	token, err := SignRefreshToken("user-2", "org-2", testSecret)
	require.NoError(t, err)

	claims, err := VerifyToken(token, testSecret)
	require.NoError(t, err)

	assert.Equal(t, "user-2", claims.UserID)
	assert.Equal(t, "org-2", claims.OrgID)
	assert.Empty(t, claims.Role, "refresh token should not carry role")
}

func TestVerifyToken_WrongSecret(t *testing.T) {
	token, err := SignAccessToken("user-1", "org-1", "admin", testSecret)
	require.NoError(t, err)

	_, err = VerifyToken(token, "wrong-secret")
	assert.Error(t, err)
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	now := time.Now()
	claims := Claims{
		UserID: "user-1",
		OrgID:  "org-1",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-1",
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testSecret))
	require.NoError(t, err)

	_, err = VerifyToken(signed, testSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is expired")
}

func TestVerifyToken_MissingClaims(t *testing.T) {
	// Token with no custom claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	signed, err := token.SignedString([]byte(testSecret))
	require.NoError(t, err)

	claims, err := VerifyToken(signed, testSecret)
	require.NoError(t, err)
	assert.Empty(t, claims.UserID, "should parse but have empty user ID")
}

func TestVerifyToken_InvalidFormat(t *testing.T) {
	_, err := VerifyToken("not.a.valid.jwt", testSecret)
	assert.Error(t, err)
}
