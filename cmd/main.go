package main

import (
    "log"
    "os"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "github.com/rotacerta/backend/internal"
)

func main() {
    _ = godotenv.Load()
    dsn := os.Getenv("DATABASE_URL")
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatalf("failed to connect database: %v", err)
    }
    if err := internal.AutoMigrate(db); err != nil {
        log.Fatalf("auto-migrate error: %v", err)
    }

    r := gin.Default()
    r.Use(internal.CORSMiddleware())

    // Saúde da API
    r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

    // Público
    r.POST("/auth/register", internal.RegisterHandler(db))
    r.POST("/auth/login", internal.LoginHandler(db))
    r.POST("/auth/recover", internal.PasswordRecoverHandler(db))

    // Billing, webhook
    r.POST("/billing/start", internal.StartTrialOrBilling(db))
    r.POST("/billing/webhook", internal.BillingWebhook(db))

    // WhatsApp webhook
    r.POST("/whatsapp/webhook", internal.WhatsAppWebhook(db))

    // Protegido (JWT + assinatura ativa)
    api := r.Group("/api")
    api.Use(internal.AuthMiddleware(), internal.ActiveSubscriptionMiddleware(db))
    {
        api.GET("/profile", internal.ProfileHandler(db))
        api.GET("/deliveries", internal.ListDeliveries(db))
        api.POST("/deliveries", internal.CreateDelivery(db))
        api.PUT("/deliveries/:id/status", internal.UpdateStatus(db))
        api.GET("/drivers", internal.ListDrivers(db))
        api.GET("/logs", internal.LogsHandler(db))
        api.GET("/report", internal.ReportHandler(db))
        api.POST("/notify", internal.NotifyWhatsAppHandler(db))
    }

    // Painel admin (JWT + role = hub/admin)
    admin := r.Group("/admin")
    admin.Use(internal.AuthMiddleware(), internal.AdminOnly())
    {
        admin.GET("/dashboard", internal.AdminDashboard(db))
        admin.GET("/users", internal.AdminListUsers(db))
        admin.POST("/drivers", internal.AdminCreateDriver(db))
        admin.DELETE("/users/:id", internal.AdminDeleteUser(db))
    }

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    r.Run(":" + port)
}
