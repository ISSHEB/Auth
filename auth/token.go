package auth

import (
	"github.com/golang-jwt/jwt"
	"time"
)

func CreateTokenPair(userID string) (string, string, error) {

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userID,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	accessTokenString, err := accessToken.SignedString([]byte("secret"))
	if err != nil {
		return "", "", err
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userID,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	refreshTokenString, err := refreshToken.SignedString([]byte("secret"))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}
