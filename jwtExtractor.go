package jwtExtractor

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type JWTExtractor struct {
	parser *jwt.Parser
}

func NewJWTExtractor(parser *jwt.Parser) *JWTExtractor {
	return &JWTExtractor{
		parser: parser,
	}
}

func (e *JWTExtractor) ExtractAudience(TokenString string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(TokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	aud, audErr := token.Claims.GetAudience()
	if audErr != nil {
		return "", err
	}

	if len(aud) == 0 {
		return "", errors.New("audience claim is empty")
	}

	return aud[0], err
}

func (e *JWTExtractor) ExtractSubject(TokenString string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(TokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	aud, audErr := token.Claims.GetSubject()
	if audErr != nil {
		return "", err
	}
	return aud, err
}

func (e *JWTExtractor) ExtractClientId(TokenString string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(TokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	return token.Claims.(jwt.MapClaims)["client_id"].(string), nil
}
