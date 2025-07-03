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

    // TODO guid as primary key
    _, err = postgres.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            guid CHAR(20) NOT NULL,
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

// returns both guid and error if expired
func validateAccessToken(tokenString string) (guid string, err error) {
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

        guid, err := validateAccessToken(tokenString)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
                "error": err.Error(),
            })
            return
        }

        c.Set("guid", guid)
        c.Next()
    }
}

func issueAccessToken(guid string) (string, error) {
    now := time.Now().Unix()

    return jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
        "iss": "medods-auth-service",
        "sub": guid,
        "iat": now,
        "exp": now + 30,  // short for testing purposes
        // TODO consider parametrizing through .env
    }).SignedString([]byte("TODO-private-key"))
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
        access, err := issueAccessToken(guid)

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        refresh := uuid.New().String()  // TODO not in base64 because dashes
        refreshHash, err := bcrypt.GenerateFromPassword([]byte(refresh), 10)

        if err != nil {
            panic(err.Error())
        }

        _, err = postgres.Exec(context.Background(), `
            INSERT INTO refresh_tokens (guid, token, expires)
            VALUES ($1, $2, $3);
        `, guid, refreshHash, time.Now().Add(time.Hour * 48))  // TODO .env parameter?

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

    type RefreshBody struct {
        Access string `json:"access"`
        Refresh string `json:"refresh"`
    }

    g.POST("/refresh", func(c *gin.Context) {
        var body RefreshBody
        if err := c.ShouldBindJSON(&body); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        guid, _ := validateAccessToken(body.Access)
        if guid == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
            return
        }

        var pg_refresh string
        var expires time.Time
        err := postgres.QueryRow(context.Background(), `
            SELECT token, expires FROM refresh_tokens WHERE guid=$1
        `, guid).Scan(&pg_refresh, &expires)

        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh tokens for this GUID"})
            return
        }

        if time.Now().After(expires) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(pg_refresh), []byte(body.Refresh)) != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token doesn't match"})
            return
        }

        access, err := issueAccessToken(guid)

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "access": access,
            // TODO issue refresh token, invalidate the old one
        })
    })

    g.GET("/guid", AuthMiddleware(), func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"guid": c.MustGet("guid")})
    })

    g.Run()
}
