package main

// User representa motorista ou hub user
type User struct {
    ID       uint   `gorm:"primaryKey"`
    Name     string `gorm:"size:120"`
    Phone    string `gorm:"uniqueIndex"`
    Password string `json:"-"`
}

// Delivery representa uma entrega
type Delivery struct {
    ID        uint    `gorm:"primaryKey"`
    DriverID  uint    // FK para User.ID
    Customer  string  // nome do cliente
    Address   string  // endereço de entrega
    Status    string  // pending|started|arrived|finished|failed
    Latitude  float64 // opcional
    Longitude float64 // opcional
}