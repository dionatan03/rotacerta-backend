package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"log"
)

// Envia mensagem WhatsApp via API
func SendWhatsAppMessage(phone, message string) error {
	apiURL := os.Getenv("WHATSAPP_API_URL")
	apiToken := os.Getenv("WHATSAPP_API_TOKEN")
	if apiURL == "" || apiToken == "" {
		return errors.New("integração WhatsApp não configurada (env vars)")
	}

	body := map[string]interface{}{
		"phone":   phone,
		"message": message,
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("erro ao criar requisição: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("erro na requisição: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		log.Printf("WhatsApp erro %d: %s", resp.StatusCode, buf.String()) // só log interno
		return fmt.Errorf("falha no envio WhatsApp (status %d)", resp.StatusCode)
	}
	return nil
}
