// utils хранит унитарные функции и обьекты, которые сложно приписать к какому-либо конкретному пакету.
package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// Message кодирует два параметры в map'у [string]interface и возвращает ее.
func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

// Respond кодирует data в json и записывает его в тело ответа w.
func Respond(w http.ResponseWriter, data map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// ValidateEmail проверяет корректность адреса электронной почты
func ValidateEmail(email string) error {
	if len(email) > 254 {
		return errors.New("адрес электронной почты слишком длинный (максимум 254 символа)")
	}

	re := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	if !re.MatchString(email) {
		return errors.New("некорректный формат адреса электронной почты")
	}

	return nil
}

// ValidatePassword проверяет надежность пароля. Возвращает статус и ошибку в случае неудачи
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("пароль должен содержать как минимум 8 символов")
	}
	if len(password) > 254 {
		return errors.New("пароль слишком длинный (максимум 254 символа)")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("пароль должен содержать хотя бы одну заглавную букву")
	}
	if !hasLower {
		return errors.New("пароль должен содержать хотя бы одну строчную букву")
	}
	if !hasNumber {
		return errors.New("пароль должен содержать хотя бы одну цифру")
	}
	if !hasSpecial {
		return errors.New("пароль должен содержать хотя бы один специальный символ")
	}

	return nil
}

// ExtractToken извлекает токен из заголовка запроса.
func ExtractToken(r *http.Request, headerName string) (string, error) {
	bearerToken := r.Header.Get(headerName)
	if bearerToken == "" {
		return "", fmt.Errorf("отсутствует токен аутентификации")
	}

	parts := strings.Split(bearerToken, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("неверный формат токена аутентификации")
	}

	return parts[1], nil
}
