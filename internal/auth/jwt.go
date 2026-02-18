package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer             = "esg-platform"
	accessTokenExpiry  = 15 * time.Minute
	refreshTokenExpiry = 7 * 24 * time.Hour
	mfaTokenExpiry     = 5 * time.Minute
)

// TokenTypeMFA identifies a short-lived MFA challenge token.
const TokenTypeMFA = "mfa"

// Claims are the JWT claims carried in access tokens.
type Claims struct {
	UserID string `json:"uid"`
	OrgID  string `json:"oid"`
	Role   string `json:"role,omitempty"`
	Type   string `json:"type,omitempty"` // "mfa" for MFA challenge tokens; empty for access tokens
	jwt.RegisteredClaims
}

// SignAccessToken creates a signed HS256 JWT access token (15-minute expiry).
func SignAccessToken(userID, orgID, role, secret string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// SignRefreshToken creates a signed HS256 JWT refresh token (7-day expiry).
// Does NOT carry role — role is resolved from DB on refresh.
func SignRefreshToken(userID, orgID, secret string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		OrgID:  orgID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshTokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// SignMFAToken creates a short-lived JWT (5-minute expiry) for the MFA challenge step.
// The token carries Type="mfa" and includes the user's role so we can issue a full
// access token after TOTP verification without an extra DB lookup.
func SignMFAToken(userID, orgID, role, secret string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
		Type:   TokenTypeMFA,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(mfaTokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// VerifyToken parses and validates a JWT token string, returning the claims.
func VerifyToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// AccessTokenExpiry returns the access token lifetime (for expires_in response field).
func AccessTokenExpiry() time.Duration {
	return accessTokenExpiry
}
