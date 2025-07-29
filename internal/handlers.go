package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
)

// AuthMiddleware demo (aceita só “demo-token”)
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "demo-token" {
            c.Next()
            return
        }
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        c.Abort()
    }
}
