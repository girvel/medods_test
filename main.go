package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func InitPostgres() (*pgx.Conn, error) {
    // TODO log initializing postgres

    user := os.Getenv("POSTGRES_USER")
    if user == "" {
        return nil, fmt.Errorf("$POSTGRES_USER not set")
    }

    password := os.Getenv("POSTGRES_PASSWORD")
    if password == "" {
        return nil, fmt.Errorf("$POSTGRES_PASSWORD not set")
    }

    pg_address := fmt.Sprintf("postgres://%s:%s@db:5432/credentials", user, password)
    postgres, err := pgx.Connect(context.Background(), pg_address)

    if err != nil {
        return nil, err
    }

    _, err = postgres.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            token CHAR(60) NOT NULL,
            expires TIMESTAMP NOT NULL
        );
    `)

    if err != nil {
        return nil, err
    }

    // TODO log connected to version X

    return postgres, nil
}

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error": "Authorization header missing",
            })
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error": "'Bearer ' prefix missing",
            })
            return
        }

        // notice: handles token expiration automatically
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, jwt.ErrSignatureInvalid
            }
            return []byte("TODO-private-key"), nil
        })

        if err != nil || !token.Valid {
            var reason string
            if err != nil {
                reason = err.Error()
            } else {
                reason = "Invalid token"
            }

            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error": reason,
            })
            return
        }

        claims := token.Claims.(jwt.MapClaims)
        c.Set("guid", claims["sub"])
        c.Next()
    }
}

func main() {
    postgres, err := InitPostgres()
    if err != nil {
        panic(err.Error())  // TODO log
    }
    defer postgres.Close(context.Background())

    g := gin.Default()

    g.POST("/login", func(c *gin.Context) {
        guid := c.Query("guid")
        if guid == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "missing `guid` query parameter"})
            return
        }

        // TODO validate GUID

        now := time.Now().Unix()

        access, err := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
            "iss": "medods-auth-service",
            "sub": guid,
            "iat": now,
            "exp": now + 30,  // short for testing purposes
            // TODO consider parametrizing through .env
        }).SignedString([]byte("TODO-private-key"))

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        refresh := uuid.New().String()
        refreshHash, err := bcrypt.GenerateFromPassword([]byte(refresh), 10)

        if err != nil {
            panic(err.Error())
        }

        _, err = postgres.Exec(context.Background(), `
            INSERT INTO refresh_tokens (token, expires)
            VALUES ($1, $2);
        `, refreshHash, time.Now().Add(time.Hour * 48))  // TODO .env parameter?

        // TODO refresh token cleanup

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "access": access,
            "refresh": refresh,
        })
    })

    g.GET("/guid", AuthMiddleware(), func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"guid": c.MustGet("guid")})
    })

    g.Run()
}
