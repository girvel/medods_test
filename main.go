package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
    "os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

func connect_to_postgres() (*pgx.Conn, error) {
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

    return postgres, nil
}

func main() {
    postgres, err := connect_to_postgres()
    if err != nil {
        panic(err.Error())  // TODO log
    }
    defer postgres.Close(context.Background())

    var version string
    err = postgres.QueryRow(context.Background(), "SELECT VERSION()").Scan(&version)
    if err != nil {
        panic(err.Error())
    }
    fmt.Println(version)

    g := gin.Default()

    g.POST("/token", func (c *gin.Context) {
        guid := c.Query("guid")
        if guid == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "missing `guid` query parameter"})
            return
        }

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
        refresh_hash, err := bcrypt.GenerateFromPassword([]byte(refresh), 10)

        if err != nil {
            panic(err.Error())
        }

        _ = refresh_hash  // TODO postgres

        c.JSON(http.StatusOK, gin.H{
            "access": access,
            "refresh": refresh,
        })
    })

    g.Run()
}
