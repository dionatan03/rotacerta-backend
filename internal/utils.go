package internal

import (
    "math/rand"
    "regexp"
    "strconv"
    "strings"
    "time"
    "github.com/gin-gonic/gin"
)

// Retorna timestamp UTC atual
func Now() time.Time {
    return time.Now().UTC()
}

// Valida telefone (10~15 dígitos)
func IsValidPhone(phone string) bool {
    r := regexp.MustCompile(`^\d{10,15}$`)
    return r.MatchString(phone)
}

// Remove caracteres não numéricos
func SanitizePhone(phone string) string {
    r := regexp.MustCompile(`\D`)
    return r.ReplaceAllString(phone, "")
}

// Valida email simples
func IsValidEmail(email string) bool {
    r := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
    return r.MatchString(email)
}

// Converte string para uint com default
func ParseUint(s string, def uint) uint {
    n, err := strconv.ParseUint(s, 10, 32)
    if err != nil {
        return def
    }
    return uint(n)
}

// Gera código de 6 dígitos
func GenerateCode() string {
    return strconv.Itoa(100000 + rand.Intn(900000))
}

// Data de hoje em "YYYY-MM-DD"
func TodayString() string {
    return time.Now().UTC().Format("2006-01-02")
}

// Checa se é final de semana
func IsWeekend(t time.Time) bool {
    weekday := t.UTC().Weekday()
    return weekday == time.Saturday || weekday == time.Sunday
}

// Mascarar telefone
func MaskPhone(phone string) string {
    clean := SanitizePhone(phone)
    if len(clean) <= 4 {
        return clean
    }
    return strings.Repeat("*", len(clean)-4) + clean[len(clean)-4:]
}

// Responde erro padronizado
func RespondError(c *gin.Context, status int, msg string) {
    c.AbortWithStatusJSON(status, gin.H{"error": msg})
}
