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

// JWT autenticação
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        auth := c.GetHeader("Authorization")
        if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
            RespondError(c, http.StatusUnauthorized, "Token ausente")
            return
        }
        tokenString := strings.TrimPrefix(auth, "Bearer ")
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })
        if err != nil || !token.Valid {
            RespondError(c, http.StatusUnauthorized, "Token inválido")
            return
        }
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            RespondError(c, http.StatusUnauthorized, "Token inválido")
            return
        }
        userID, ok := claims["user_id"].(float64)
        if !ok {
            RespondError(c, http.StatusUnauthorized, "Token corrompido")
            return
        }
        role, ok := claims["role"].(string)
        if !ok {
            RespondError(c, http.StatusUnauthorized, "Token corrompido")
            return
        }
        active, _ := claims["active"].(bool)
        c.Set("user_id", uint(userID))
        c.Set("role", role)
        c.Set("active", active)
        c.Next()
    }
}

// Só permite usuários com assinatura ou trial ativa
func ActiveSubscriptionMiddleware(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := c.GetUint("user_id")
        var user User
        if err := db.First(&user, userID).Error; err != nil {
            RespondError(c, http.StatusUnauthorized, "Usuário não encontrado")
            return
        }
        now := Now()
        trialOk := user.TrialEndsAt != nil && user.TrialEndsAt.After(now)
        var sub Subscription
        hasSub := db.Where("user_id = ? AND active = true AND expires_at > ?", userID, now).First(&sub).Error == nil
        if !trialOk && !hasSub {
            RespondError(c, http.StatusPaymentRequired, "Assinatura expirada")
            return
        }
        c.Next()
    }
}

// Só permite admin/hub
func AdminOnly() gin.HandlerFunc {
    return func(c *gin.Context) {
        role := c.GetString("role")
        if role != "hub" && role != "admin" {
            RespondError(c, http.StatusForbidden, "Acesso restrito")
            return
        }
        c.Next()
    }
}

// CORS seguro — só libera domínio confiável
func CORSMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        allowed := []string{
            "https://seuapp.com",        // Troque pelo seu domínio real
            "https://admin.seuapp.com",  // Painel admin/hub
            "http://localhost:3000",     // Só em desenvolvimento!
        }
        origin := c.GetHeader("Origin")
        isAllowed := false
        for _, o := range allowed {
            if o == origin {
                isAllowed = true
                break
            }
        }
        if isAllowed {
            c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
        }
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    }
}
