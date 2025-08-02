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
    // Nunca suba .env pro GitHub (.gitignore sempre!)
    _ = godotenv.Load()

    // Variável de ambiente DATABASE_URL precisa estar setada no Railway
    dsn := os.Getenv("DATABASE_URL")
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatalf("failed to connect database: %v", err)
    }
    if err := internal.AutoMigrate(db); err != nil {
        log.Fatalf("auto-migrate error: %v", err)
    }

    r := gin.Default()

    // CORS: só liberar origem segura (ajuste internal.CORSMiddleware se necessário)
    r.Use(internal.CORSMiddleware())

    // Health check
    r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

    // Público
    r.POST("/auth/register", internal.RegisterHandler(db))
    r.POST("/auth/login", internal.LoginHandler(db))
    r.POST("/auth/recover", internal.PasswordRecoverHandler(db))
    r.POST("/billing/start", internal.StartTrialOrBilling(db))
    r.POST("/billing/webhook", internal.BillingWebhook(db))
    r.POST("/whatsapp/webhook", internal.NotifyWhatsAppHandler(db))

    // Painel público admin (cuidado: mantenha rotas apenas para informações não sensíveis!)
    r.GET("/admin/logs", internal.ListLogs(db))            // Filtrar dados sensíveis se necessário!
    r.GET("/admin/deliveries", internal.ListAllDeliveries(db))

    // API protegida (JWT + assinatura ativa)
    api := r.Group("/api")
    api.Use(
        internal.AuthMiddleware(),             // JWT obrigatório
        internal.ActiveSubscriptionMiddleware(db), // Trial/assinatura obrigatória
    )
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

    // Painel admin/HUB (só quem tem role de admin/hub)
    admin := r.Group("/admin")
    admin.Use(
        internal.AuthMiddleware(), // JWT obrigatório
        internal.AdminOnly(),      // Apenas admin/hub
    )
    {
        admin.GET("/dashboard", internal.AdminDashboard(db))
        admin.GET("/users", internal.AdminListUsers(db))
        admin.POST("/drivers", internal.AdminCreateDriver(db))
        admin.DELETE("/users/:id", internal.AdminDeleteUser(db))
    }

    // Porta de produção sempre em variável, default 8080
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    if err := r.Run(":" + port); err != nil {
        log.Fatalf("falha ao rodar servidor: %v", err)
    }
}