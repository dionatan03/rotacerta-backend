package internal

import (
	"gorm.io/gorm"
	"time"
)

// Usuário do sistema
type User struct {
	gorm.Model
	Name          string
	Phone         string `gorm:"unique;not null"`
	PasswordHash  string `gorm:"not null"`
	Role          string // "driver", "hub", "admin"
	Deliveries    []Delivery `gorm:"foreignKey:DriverID"`
	Subscriptions []Subscription
	TrialEndsAt   *time.Time
	LastLoginAt   *time.Time
	Blocked       bool
}

// Entrega
type Delivery struct {
	gorm.Model
	Address     string
	Status      string // "pendente", "em_rota", "entregue", "ausente"
	DriverID    uint
	Driver      *User  // FK para User (Driver)
	Description string
	CreatedBy   uint   // ID do hub/admin que criou
}

// Assinatura
type Subscription struct {
	gorm.Model
	UserID    uint
	Active    bool
	ExpiresAt time.Time
	BillingID string
	Type      string // "google", "stripe"
}

// Log de eventos do sistema
type Log struct {
	gorm.Model
	UserID    uint
	Message   string
	EventType string
}

// Migration automática
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&User{}, &Delivery{}, &Subscription{}, &Log{})
}
