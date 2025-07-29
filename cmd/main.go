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

// Defina as structs User e Delivery se não estiverem em outro arquivo
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

// Defina o AuthMiddleware se não estiver em outro arquivo
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lógica de autenticação aqui (exemplo: permitir tudo)
		c.Next()
	}
}

func main() {
	// carrega .env (opcional em Railway)
	_ = godotenv.Load()

	// conecta no banco: PostgreSQL se existir DATABASE_URL, senão SQLite local
	var db *gorm.DB
	var err error
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		// usa SQLite local: arquivo rotacerta.db
		db, err = gorm.Open(sqlite.Open("rotacerta.db"), &gorm.Config{})
	} else {
		// usa Postgres (Railway, Supabase, etc)
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	}
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// auto‑migrate
	db.AutoMigrate(&User{}, &Delivery{})

	// servidor HTTP
	r := gin.Default()
	r.Use(AuthMiddleware())

	// Exemplo de rota
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	r.Run() // roda na porta padrão 8080
}
