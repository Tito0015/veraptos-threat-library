package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func parseVuln(token string) (*jwt.Token, error) {
	// ruleid: jwt-none-alg-go
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
}

func parseUnverified(token string) (*jwt.Token, error) {
	// ruleid: jwt-none-alg-go-parse-unverified
	return jwt.ParseUnverified(token, jwt.MapClaims{})
}

func parseSafe(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		// ok: jwt-none-alg-go
		return []byte("secret"), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
}

func parseSafeSwitch(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			// ok: jwt-none-alg-go
			return []byte("secret"), nil
		default:
			return nil, fmt.Errorf("bad alg")
		}
	})
}
