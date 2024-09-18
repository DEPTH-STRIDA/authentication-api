package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateStrongPassword(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func main() {
	password, err := generateStrongPassword(64)
	if err != nil {
		fmt.Println("Ошибка при генерации пароля:", err)
		return
	}
	fmt.Println("Сгенерированный пароль:", password)
}
