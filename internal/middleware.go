package internal

import (
    "net/http"
    "os"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"
    "gorm.io/gorm"
)

var jwtKey = []byte(getEnv("JWT_SECRET", "rotacerta-ultra-secreto"))

func getEnv(k, d string) string {
    v := os.Getenv(k)
    if v == "" { return d }
    return v
}

// Autenticação JWT
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        auth := c.GetHeader("Authorization")
        if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token ausente"})
            return
        }
        tokenString := strings.TrimPrefix(auth, "Bearer ")
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })
        if err != nil || !token.Valid {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token inválido"})
            return
        }
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token inválido"})
            return
        }
        c.Set("user_id", uint(claims["user_id"].(float64)))
        c.Set("role", claims["role"].(string))
        c.Set("active", claims["active"].(bool))
        c.Next()
    }
}

// Protege endpoints para só acessar se assinatura/trial ativa
func ActiveSubscriptionMiddleware(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := c.GetUint("user_id")
        var user User
        if err := db.First(&user, userID).Error; err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "usuário não encontrado"})
            return
        }
        now := Now()
        trialOk := user.TrialEndsAt != nil && user.TrialEndsAt.After(now)
        var sub Subscription
        hasSub := db.Where("user_id = ? AND active = true AND expires_at > ?", userID, now).First(&sub).Error == nil
        if !trialOk && !hasSub {
            c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{"error": "assinatura expirada"})
            return
        }
        c.Next()
    }
}

// Só permite admin ou hub acessar
func AdminOnly() gin.HandlerFunc {
    return func(c *gin.Context) {
        role := c.GetString("role")
        if role != "hub" && role != "admin" {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "acesso restrito"})
            return
        }
        c.Next()
    }
}

// CORS Middleware
func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    }
}