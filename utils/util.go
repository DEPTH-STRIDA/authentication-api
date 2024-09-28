// utils хранит унитарные функции и обьекты, которые сложно приписать к какому-либо конкретному пакету.
package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

	// // Регулярное выражение для проверки формата email
	// // ^                   - начало строки
	// // [a-z0-9._%+\-]+     - одна или более букв, цифр, точек, подчеркиваний, процентов, плюсов или дефисов
	// // @                   - символ @
	// // [a-z0-9.\-]+        - одна или более букв, цифр, точек или дефисов
	// // \.                  - точка
	// // [a-z]{2,4}          - от 2 до 4 букв (домен верхнего уровня)
	// // $                   - конец строки
	// emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)

	// // Проверяем, соответствует ли email заданному регулярному выражению
	// if !emailRegex.MatchString(email) {
	// 	return fmt.Errorf("invalid email format")
	// }

	// // Проверяем длину email (максимум 254 символа согласно RFC 5321)
	// if len(email) > 254 {
	// 	return fmt.Errorf("email is too long")
	// }

	return nil
}

// ValidatePassword проверяет надежность пароля. Возвращает статус и ошибку в случае неудачи
func ValidatePassword(password string) error {
	// Проверяем минимальную длину пароля (6 символов)
	// if len(password) < 6 {
	// 	return fmt.Errorf("password must be at least 6 characters long")
	// }

	// // Проверяем максимальную длину пароля (128 символов)
	// if len(password) > 128 {
	// 	return fmt.Errorf("password is too long")
	// }

	// // Флаги для проверки наличия различных типов символов в пароле
	// var hasUpper, hasLower, hasNumber, hasSpecial bool

	// // Проходим по каждому символу в пароле
	// for _, char := range password {
	// 	switch {
	// 	case unicode.IsUpper(char):
	// 		hasUpper = true
	// 	case unicode.IsLower(char):
	// 		hasLower = true
	// 	case unicode.IsNumber(char):
	// 		hasNumber = true
	// 	case unicode.IsPunct(char) || unicode.IsSymbol(char):
	// 		hasSpecial = true
	// 	}
	// }

	// // Проверяем, содержит ли пароль все необходимые типы символов
	// if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
	// 	return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	// }

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
