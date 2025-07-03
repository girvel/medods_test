package medods_test

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func IssueAccessToken(guid string) (string, error) {
    now := time.Now().Unix()

    return jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
        "iss": "medods-auth-service",
        "sub": guid,
        "iat": now,
        "exp": now + 30,  // short for testing purposes
        // TODO consider parametrizing through .env
    }).SignedString([]byte("TODO-private-key"))
}

// returns both guid and error if expired
func ValidateAccessToken(tokenString string) (guid string, err error) {
    // notice: handles token expiration automatically
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, jwt.ErrSignatureInvalid
        }
        return []byte("TODO-private-key"), nil
    })

    if token == nil {
        return "", err
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok {
        if sub, ok := claims["sub"]; ok {
            return sub.(string), err
        }
    }

    if err != nil {
        return "", err
    } else {
        return "", fmt.Errorf("Invalid token")
    }
}
