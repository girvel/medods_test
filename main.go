package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
)

func main() {
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
