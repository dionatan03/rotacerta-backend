package internal

import (
  "fmt"
  "net/http"
  "os"
  "strconv"
  "time"
  "github.com/gin-gonic/gin"
  "github.com/golang-jwt/jwt/v5"
  "golang.org/x/crypto/bcrypt"
  "gorm.io/gorm"
)

// ========== RATE LIMITING SIMPLES (por IP, memória local) ==========
var waRateLimit = make(map[string]struct {
	Count     int
	LastReset time.Time
})

func rateLimit(ip string, max int) bool {
	now := time.Now()
	rl := waRateLimit[ip]
	if rl.LastReset.IsZero() || now.Sub(rl.LastReset) > time.Hour {
		rl.Count = 0
		rl.LastReset = now
	}
	rl.Count++
	waRateLimit[ip] = rl
	return rl.Count > max
}

// ========== SALVA LOG ==========

func SaveLog(db *gorm.DB, userID uint, event, message string) {
	db.Create(&Log{
		UserID:    userID,
		EventType: event,
		Message:   message,
	})
}

// ========== USUÁRIO / AUTENTICAÇÃO ==========

func RegisterHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name     string `json:"name" binding:"required"`
			Phone    string `json:"phone" binding:"required"`
			Password string `json:"password" binding:"required"`
			Role     string `json:"role" binding:"required"` // "driver" ou "hub"
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		if req.Role != "driver" && req.Role != "hub" {
			RespondError(c, 400, "Tipo de usuário inválido")
			return
		}
		if !IsValidPhone(req.Phone) {
			RespondError(c, 400, "Telefone inválido")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 14)
		user := User{Name: req.Name, Phone: req.Phone, PasswordHash: string(hash), Role: req.Role}
		if err := db.Create(&user).Error; err != nil {
			RespondError(c, 409, "Telefone já cadastrado")
			return
		}
		days := 3
		if os.Getenv("TRIAL_DAYS") != "" {
			days, _ = strconv.Atoi(os.Getenv("TRIAL_DAYS"))
		}
		trial := time.Now().AddDate(0, 0, days)
		user.TrialEndsAt = &trial
		db.Save(&user)
		SaveLog(db, user.ID, "register", fmt.Sprintf("Cadastro de %s (%s)", req.Name, req.Phone))
		c.JSON(http.StatusCreated, gin.H{"message": "Cadastrado com sucesso", "trial_end": trial})
	}
}

func LoginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Phone    string `json:"phone" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Campos obrigatórios ausentes")
			return
		}
		if rateLimit(c.ClientIP(), 10) {
			RespondError(c, 429, "Limite de tentativas atingido. Tente novamente em 1h.")
			SaveLog(db, 0, "ratelimit_login", "Rate limit login atingido para "+c.ClientIP())
			return
		}
		var user User
		if err := db.Where("phone = ?", req.Phone).First(&user).Error; err != nil {
			RespondError(c, 401, "Usuário não encontrado")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			RespondError(c, 401, "Senha inválida")
			return
		}
		if user.Blocked {
			RespondError(c, 403, "Usuário bloqueado")
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
		SaveLog(db, user.ID, "login", fmt.Sprintf("Login bem-sucedido %s", user.Phone))
		c.JSON(http.StatusOK, gin.H{"token": tokenString, "active": active})
	}
}

func PasswordRecoverHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct{ Phone string `json:"phone" binding:"required"` }
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		var user User
		if err := db.Where("phone = ?", req.Phone).First(&user).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"message": "Se existir, receberá instruções"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Se existir, receberá instruções"})
	}
}

func ProfileHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetUint("user_id")
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			RespondError(c, 404, "Usuário não encontrado")
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

// ========== LOGS E ADMIN ==========

func ListLogs(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("role")
		if role != "admin" && role != "hub" {
			RespondError(c, 403, "Apenas admin/hub")
			return
		}
		var logs []Log
		db.Order("created_at desc").Limit(100).Find(&logs)
		c.JSON(http.StatusOK, logs)
	}
}

// ========== ENTREGAS ==========

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
			RespondError(c, 403, "Apenas hub pode criar entrega")
			return
		}
		var req struct {
			Address     string `json:"address" binding:"required"`
			Description string `json:"description"`
			DriverID    uint   `json:"driver_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		var driver User
		if err := db.First(&driver, req.DriverID).Error; err != nil {
			RespondError(c, 400, "Motorista não encontrado")
			return
		}
		delivery := Delivery{
			Address:     req.Address,
			Status:      "pendente",
			Description: req.Description,
			DriverID:    req.DriverID,
			CreatedBy:   userID,
		}
		db.Create(&delivery)
		SaveLog(db, userID, "create_delivery", fmt.Sprintf("Entrega criada para motorista %d", req.DriverID))
		c.JSON(http.StatusCreated, gin.H{"delivery_id": delivery.ID})
	}
}

func UpdateStatus(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var req struct{ Status string `json:"status" binding:"required"` }
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		var delivery Delivery
		if db.First(&delivery, id).Error != nil {
			RespondError(c, 404, "Entrega não encontrada")
			return
		}
		role := c.GetString("role")
		userID := c.GetUint("user_id")
		if role == "driver" && delivery.DriverID != userID {
			RespondError(c, 403, "Não autorizado")
			return
		}
		delivery.Status = req.Status
		db.Save(&delivery)
		c.JSON(http.StatusOK, delivery)
	}
}

// ========== PAINEL ADMIN / HUB ==========

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
		safeUsers := make([]gin.H, 0)
		for _, u := range users {
			safeUsers = append(safeUsers, gin.H{
				"id":    u.ID,
				"name":  u.Name,
				"phone": u.Phone,
				"role":  u.Role,
			})
		}
		c.JSON(http.StatusOK, safeUsers)
	}
}

func AdminCreateDriver(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name     string `json:"name" binding:"required"`
			Phone    string `json:"phone" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 14)
		driver := User{Name: req.Name, Phone: req.Phone, PasswordHash: string(hash), Role: "driver"}
		if err := db.Create(&driver).Error; err != nil {
			RespondError(c, 409, "Telefone já cadastrado")
			return
		}
		SaveLog(db, driver.ID, "admin_create_driver", "Motorista criado via painel")
		c.JSON(http.StatusCreated, gin.H{
			"id":    driver.ID,
			"name":  driver.Name,
			"phone": driver.Phone,
			"role":  driver.Role,
		})
	}
}

func AdminDeleteUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		db.Delete(&User{}, id)
		SaveLog(db, 0, "admin_delete_user", fmt.Sprintf("User %s deletado", id))
		c.JSON(http.StatusOK, gin.H{"deleted": true})
	}
}

// ========== LOGS, RELATÓRIOS, DRIVERS ==========

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

func ListDrivers(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var drivers []User
		db.Where("role = ?", "driver").Find(&drivers)
		safeDrivers := make([]gin.H, 0)
		for _, d := range drivers {
			safeDrivers = append(safeDrivers, gin.H{
				"id":    d.ID,
				"name":  d.Name,
				"phone": d.Phone,
			})
		}
		c.JSON(http.StatusOK, safeDrivers)
	}
}

func ListAllDeliveries(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("role")
		if role != "admin" && role != "hub" {
			RespondError(c, 403, "Apenas admin/hub")
			return
		}
		var deliveries []Delivery
		db.Find(&deliveries)
		c.JSON(http.StatusOK, deliveries)
	}
}

// ========== NOTIFICAÇÃO WHATSAPP (Segura) ==========

func NotifyWhatsAppHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("role")
		if role == "" {
			RespondError(c, 401, "Não autorizado")
			return
		}
		if rateLimit(c.ClientIP(), 10) {
			RespondError(c, 429, "Limite de notificações atingido. Tente novamente em 1h.")
			SaveLog(db, c.GetUint("user_id"), "ratelimit", "Rate limit WhatsApp atingido para "+c.ClientIP())
			return
		}
		var req struct {
			Phone   string `json:"phone"`
			Message string `json:"message"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados inválidos")
			return
		}
		req.Phone = SanitizePhone(req.Phone)
		if !IsValidPhone(req.Phone) {
			RespondError(c, 400, "Telefone inválido")
			return
		}
		if len(req.Message) < 2 || len(req.Message) > 500 {
			RespondError(c, 400, "Mensagem deve ter entre 2 e 500 caracteres")
			return
		}
		err := SendWhatsAppMessage(req.Phone, req.Message)
		if err != nil {
			SaveLog(db, c.GetUint("user_id"), "whatsapp_error", err.Error())
			RespondError(c, 500, "Erro ao enviar notificação. Tente novamente mais tarde.")
			return
		}
		SaveLog(db, c.GetUint("user_id"), "whatsapp", "Notificação enviada para "+MaskPhone(req.Phone))
		c.JSON(200, gin.H{"ok": true, "msg": "WhatsApp enviado com sucesso"})
	}
}

// ========== BILLING/ASSINATURA ==========

func StartTrialOrBilling(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetUint("user_id")
		var user User
		if err := db.First(&user, userID).Error; err != nil {
			RespondError(c, 404, "Usuário não encontrado")
			return
		}
		now := Now()
		if user.TrialEndsAt != nil && user.TrialEndsAt.After(now) {
			c.JSON(http.StatusOK, gin.H{"message": "Trial ativo", "trial_ends_at": user.TrialEndsAt})
			return
		}
		var req struct {
			BillingType string `json:"billing_type" binding:"required"`
			BillingID   string `json:"billing_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		expires := now.AddDate(0, 1, 0)
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
			UserID    uint   `json:"user_id" binding:"required"`
			BillingID string `json:"billing_id" binding:"required"`
			Type      string `json:"type" binding:"required"`
			Event     string `json:"event" binding:"required"`
			ExpiresAt int64  `json:"expires_at"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			RespondError(c, 400, "Dados obrigatórios ausentes")
			return
		}
		var user User
		if err := db.First(&user, req.UserID).Error; err != nil {
			RespondError(c, 404, "Usuário não encontrado")
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
		RespondError(c, 400, "Evento desconhecido")
	}
}
