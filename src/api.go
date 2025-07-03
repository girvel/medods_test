package medods_test

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func authMiddleware() gin.HandlerFunc {
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

        guid, err := ValidateAccessToken(tokenString)
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

func NewAPI(db Database) *gin.Engine {
    g := gin.Default()

    g.POST("/login", func(c *gin.Context) {
        guid := c.Query("guid")
        if guid == "" {
            c.JSON(http.StatusBadRequest, gin.H{"error": "missing `guid` query parameter"})
            return
        }

        // TODO validate GUID
        access, err := IssueAccessToken(guid)

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        refresh := uuid.New().String()  // TODO not in base64 because dashes
        refreshHash, err := bcrypt.GenerateFromPassword([]byte(refresh), 10)

        if err != nil {
            panic(err.Error())
        }

        err = db.SetRefreshToken(guid, refreshHash, time.Now().Add(time.Hour * 48))
        // TODO .env parameter?
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

        guid, _ := ValidateAccessToken(body.Access)
        if guid == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
            return
        }

        refreshHash, expires, err := db.GetRefreshToken(guid)

        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh tokens for this GUID"})
            return
        }

        if time.Now().After(expires) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token expired"})
            return
        }

        if bcrypt.CompareHashAndPassword([]byte(refreshHash), []byte(body.Refresh)) != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token doesn't match"})
            return
        }

        access, err := IssueAccessToken(guid)

        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "access": access,
            // TODO issue refresh token, invalidate the old one
        })
    })

    g.GET("/guid", authMiddleware(), func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"guid": c.MustGet("guid")})
    })

    return g
}
