package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
)

// LoginHandler retorna um token demo; aqui você implementa JWT real
func LoginHandler(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var req struct {
            Phone string `json:"phone"`
            Code  string `json:"code"`
        }
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        // TODO: verificar código + gerar JWT
        c.JSON(http.StatusOK, gin.H{"token": "demo-token"})
    }
}

// ListDeliveries lista entregas do motorista (demo UserID=1)
func ListDeliveries(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var deliveries []Delivery
        db.Where("driver_id = ?", 1).Find(&deliveries)
        c.JSON(http.StatusOK, deliveries)
    }
}

// CreateDelivery cria uma nova entrega
func CreateDelivery(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        var d Delivery
        if err := c.ShouldBindJSON(&d); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        db.Create(&d)
        c.JSON(http.StatusCreated, d)
    }
}

// UpdateStatus atualiza status da entrega
func UpdateStatus(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        id := c.Param("id")
        var d Delivery
        if err := db.First(&d, id).Error; err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
            return
        }
        var in struct{ Status string `json:"status"` }
        if err := c.ShouldBindJSON(&in); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        d.Status = in.Status
        db.Save(&d)
        c.JSON(http.StatusOK, d)
    }
}