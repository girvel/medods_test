package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
    g := gin.Default()
    g.GET("/ping", func (c *gin.Context) {
        c.JSON(http.StatusOK, gin.H {"pong": "pong"})
    })
    g.Run()
}
