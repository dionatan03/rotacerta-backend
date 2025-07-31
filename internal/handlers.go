package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"net/http"
	"os"
	"strconv"
	"time"
)

// ==== Usuário / Autenticação ====

func RegisterHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name     string `json:"name"`
			Phone    string `json:"phone"`
			Password string `json:"password"`
			Role     string `json:"role"` // "driver" ou "hub"
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		if req.Role != "driver" && req.Role != "hub" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tipo de usuário inválido"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 14)
		user := User{Name: req.Name, Phone: req.Phone, PasswordHash: string(hash), Role: req.Role}
		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "telefone já cadastrado"})
			return
		}
		days := 3
		if os.Getenv("TRIAL_DAYS") != "" {
			days, _ = strconv.Atoi(os.Getenv("TRIAL_DAYS"))
		}
		trial := time.Now().AddDate(0, 0, days)
		user.TrialEndsAt = &trial
		db.Save(&user)
		c.JSON(http.StatusCreated, gin.H{"message": "cadastrado com sucesso", "trial_end": trial})
	}
}

func LoginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Phone    string `json:"phone"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		var user User
		if err := db.Where("phone = ?", req.Phone).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "usuário não encontrado"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "senha inválida"})
			return
		}
		if user.Blocked {
			c.JSON(http.StatusForbidden, gin.H{"error": "usuário bloqueado"})
			return
		}
		active := false
		now := Now()
		if user.TrialEndsAt != nil && user.TrialEndsAt.After(now) {
			active = true
		}
		var sub Subscription
		if db.Where("user_id = ? AND active = true AND expires_at > ?", user.ID, now).First(&sub).Error == nil {
			active = true
		}
		user.LastLoginAt = &now
		db.Save(&user)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": user.ID,
			"role":    user.Role,
			"exp":     now.Add(24 * time.Hour).Unix(),
			"active":  active,
		})
		tokenString, _ := token.SignedString(jwtKey)
		c.JSON(http.StatusOK, gin.H{"token": tokenString, "active": active})
	}
}

func PasswordRecoverHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct{ Phone string }
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		var user User
		if err := db.Where("phone = ?", req.Phone).First(&user).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "usuário não encontrado"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "instruções enviadas"})
	}
}

func ProfileHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetUint("user_id")
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "usuário não encontrado"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"id":            user.ID,
			"name":          user.Name,
			"phone":         user.Phone,
			"role":          user.Role,
			"trial_ends_at": user.TrialEndsAt,
		})
	}
}

// ==== Entregas ====

func ListDeliveries(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var deliveries []Delivery
		role := c.GetString("role")
		userID := c.GetUint("user_id")
		if role == "driver" {
			db.Where("driver_id = ?", userID).Order("created_at desc").Find(&deliveries)
		} else {
			db.Order("created_at desc").Find(&deliveries)
		}
		c.JSON(http.StatusOK, deliveries)
	}
}

func CreateDelivery(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        role := c.GetString("role")
        userID := c.GetUint("user_id")
        if role != "hub" && role != "admin" {
            c.JSON(http.StatusForbidden, gin.H{"error": "apenas hub pode criar entrega"})
            return
        }
        var req struct {
            Address     string `json:"address"`
            Description string `json:"description"`
            DriverID    uint   `json:"driver_id"`
        }
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
            return
        }
        var driver User
        if err := db.First(&driver, req.DriverID).Error; err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "motorista não encontrado"})
            return
        }
        delivery := Delivery{
            Address:     req.Address,
            Status:      "pendente",
            Description: req.Description,
            DriverID:    req.DriverID,
            CreatedBy:   userID, // Salva quem criou a entrega
        }
        db.Create(&delivery)
        c.JSON(http.StatusCreated, delivery)
    }
}

func UpdateStatus(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var req struct{ Status string }
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		var delivery Delivery
		if db.First(&delivery, id).Error != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "entrega não encontrada"})
			return
		}
		role := c.GetString("role")
		userID := c.GetUint("user_id")
		if role == "driver" && delivery.DriverID != userID {
			c.JSON(http.StatusForbidden, gin.H{"error": "não autorizado"})
			return
		}
		delivery.Status = req.Status
		db.Save(&delivery)
		// Aqui pode chamar WhatsAppNotify(delivery...) se quiser
		c.JSON(http.StatusOK, delivery)
	}
}

// ==== Motoristas, Logs, Relatórios ====

func ListDrivers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var drivers []User
		db.Where("role = ?", "driver").Find(&drivers)
		c.JSON(http.StatusOK, drivers)
	}
}

func LogsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var logs []Log
		db.Order("created_at desc").Limit(100).Find(&logs)
		c.JSON(http.StatusOK, logs)
	}
}

func ReportHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var count int64
		db.Model(&Delivery{}).Count(&count)
		c.JSON(http.StatusOK, gin.H{"total_entregas": count})
	}
}

// ==== Notificações WhatsApp ====

func NotifyWhatsAppHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Phone   string `json:"phone"`
			Message string `json:"message"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		err := WhatsAppNotify(req.Phone, req.Message)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// ==== Billing/Assinatura ====

func StartTrialOrBilling(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetUint("user_id")
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "usuário não encontrado"})
			return
		}
		now := Now()
		if user.TrialEndsAt != nil && user.TrialEndsAt.After(now) {
			c.JSON(http.StatusOK, gin.H{"message": "trial ativo", "trial_ends_at": user.TrialEndsAt})
			return
		}
		var req struct {
			BillingType string `json:"billing_type"` // "google" ou "stripe"
			BillingID   string `json:"billing_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		expires := now.AddDate(0, 1, 0) // 1 mês
		sub := Subscription{
			UserID:    user.ID,
			Active:    true,
			ExpiresAt: expires,
			BillingID: req.BillingID,
			Type:      req.BillingType,
		}
		db.Create(&sub)
		c.JSON(http.StatusOK, gin.H{"assinatura_ativa_ate": expires})
	}
}

func BillingWebhook(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			UserID    uint   `json:"user_id"`
			BillingID string `json:"billing_id"`
			Type      string `json:"type"`
			Event     string `json:"event"`
			ExpiresAt int64  `json:"expires_at"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		var user User
		if err := db.First(&user, req.UserID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "usuário não encontrado"})
			return
		}
		if req.Event == "payment_succeeded" || req.Event == "renewed" {
			expires := time.Unix(req.ExpiresAt, 0)
			sub := Subscription{
				UserID:    user.ID,
				Active:    true,
				ExpiresAt: expires,
				BillingID: req.BillingID,
				Type:      req.Type,
			}
			db.Create(&sub)
			c.JSON(http.StatusOK, gin.H{"assinatura_ativa_ate": expires})
			return
		}
		if req.Event == "expired" {
			db.Model(&Subscription{}).Where("user_id = ? AND active = true", user.ID).Update("active", false)
			c.JSON(http.StatusOK, gin.H{"assinatura_desativada": true})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "evento desconhecido"})
	}
}

// ==== WhatsApp ====

func WhatsAppNotify(phone, message string) error {
	apiURL := os.Getenv("WHATSAPP_API_URL")
	apiToken := os.Getenv("WHATSAPP_API_TOKEN")
	if apiURL == "" || apiToken == "" {
		return fmt.Errorf("API WhatsApp não configurada")
	}
	payload := map[string]interface{}{
		"phone":   phone,
		"message": message,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", apiURL, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("erro ao enviar WhatsApp: %d", resp.StatusCode)
	}
	return nil
}

func WhatsAppWebhook(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// ==== Painel Admin/HUB ====

func AdminDashboard(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var users, entregas, subs int64
		db.Model(&User{}).Count(&users)
		db.Model(&Delivery{}).Count(&entregas)
		db.Model(&Subscription{}).Where("active = true").Count(&subs)
		c.JSON(http.StatusOK, gin.H{
			"usuarios":           users,
			"entregas":           entregas,
			"assinaturas_ativas": subs,
		})
	}
}

func AdminListUsers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	}
}

func AdminCreateDriver(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name     string `json:"name"`
			Phone    string `json:"phone"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "dados inválidos"})
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 14)
		driver := User{Name: req.Name, Phone: req.Phone, PasswordHash: string(hash), Role: "driver"}
		if err := db.Create(&driver).Error; err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "telefone já cadastrado"})
			return
		}
		c.JSON(http.StatusCreated, driver)
	}
}

func AdminDeleteUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		db.Delete(&User{}, id)
		c.JSON(http.StatusOK, gin.H{"deleted": true})
	}
}
