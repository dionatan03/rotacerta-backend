package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name  string
	Email string
}

type Delivery struct {
	gorm.Model
	Address string
	Status  string
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Autenticação fake
		c.Next()
	}
}

func main() {
	_ = godotenv.Load()

	var db *gorm.DB
	var err error
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		db, err = gorm.Open(sqlite.Open("rotacerta.db"), &gorm.Config{})
	} else {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(&User{}, &Delivery{})

	r := gin.Default()
	r.Use(AuthMiddleware())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
