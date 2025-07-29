package main

import (
    "log"
    "os"

    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)

func main() {
    // carrega .env (opcional em Railway)
    _ = godotenv.Load()

    // conecta no Postgres
    dsn := os.Getenv("DATABASE_URL")
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatalf("failed to connect database: %v", err)
    }

    // auto‑migrate
    db.AutoMigrate(&User{}, &Delivery{})

    // servidor HTTP
    r := gin.Default()
    r.Use(AuthMiddleware())

    // endpoints
    r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
    r.POST("/auth/login", LoginHandler(db))
    r.GET("/deliveries", ListDeliveries(db))
    r.POST("/deliveries", CreateDelivery(db))
    r.PUT("/deliveries/:id/status", UpdateStatus(db))

    // porta
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    r.Run(":" + port)
}