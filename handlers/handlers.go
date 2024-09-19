package handlers

import (
	"app/models"
	"app/smtp"
	u "app/utils"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Базовый запрос. Универсален для всех обработчиков.
type BaseHttpRequest struct {
	Account models.Account `json:"account"`
}

// NewUser создание пользователя. Добавление почты в кеш, отправка сообщения, ожидание авторизации.
func NewUser(w http.ResponseWriter, r *http.Request) {
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Создание JWT токена по данным из тела
	token, ok := baseHttpRequest.Account.CreateJWTToken()
	if !ok {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	baseHttpRequest.Account.Token = token

	// Начать процесс восстановления почты
	smtp.MailManager.AuthorizeEmail(baseHttpRequest.Account.Email, baseHttpRequest.Account.Password, baseHttpRequest.Account.Token)

	// Создание мапы
	resp := u.Message(true, "The account has been successfully added for verification")
	// Добавление аккаунта
	resp["account"] = BaseHttpRequest.Account.Token
	u.Respond(w, resp)
}

// NewValidate проверка кода по токену в кеше. В случае успеха создает пользователя.
func NewValidate(w http.ResponseWriter, r *http.Request) {
	// Получение данных аккаунта из тела
	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Создание JWT токена по данным из тела
	token, ok := account.CreateJWTToken()
	if !ok {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	account.Token = token

	// Начать процесс восстановления почты
	smtp.MailManager.AuthorizeEmail(account.Email, account.Password, account.Token)

	// Создание мапы
	resp := u.Message(true, "The account has been successfully added for verification")
	// Добавление аккаунта
	resp["account"] = account.Token
	u.Respond(w, resp)
}

// Authenticate авторизация на сайте
func Authenticate(w http.ResponseWriter, r *http.Request) {
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	resp := models.Login(baseHttpRequest.Account.Email, baseHttpRequest.Account.Password)

	u.Respond(w, resp)
}

// RefreshJWTToken генерирует новый рабочий JWT токен
func RefreshJWTToken(w http.ResponseWriter, r *http.Request) {
	// Извлечение токена из заголовка
	tokenHeader := r.Header.Get("Authorization")
	// Режим токен на части
	splitted := strings.Split(tokenHeader, " ")
	// Получиться должно 2 части
	if len(splitted) != 2 {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	// Берем 2 (по порядку) часть
	tokenPart := splitted[1]

	// Подготавливаем структуру токена
	tk := &models.Token{}
	// Парсинг токена с помощью ключа из env
	_, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("token_password")), nil
	})
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Получаем сколько времени осталось, до истечения ключа
	timeUntilExpiration := time.Until(time.Unix(tk.ExpiresAt, 0))

	// Если до истечения срока больше 5 минут или токен истек, то ошибка
	if timeUntilExpiration > 5*time.Minute || timeUntilExpiration < 0 {
		u.Respond(w, u.Message(false, "Invalid request"))
	}

	// Генерация нового токена
	newToken := models.Token{
		UserId: tk.UserId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
	}

	//Шифррование и подпись токена
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, newToken).SignedString([]byte(os.Getenv("token_password")))
	if err != nil {
		log.Printf("Error creating new token: %v", err)
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	resp := u.Message(true, "tokens have been successfully updated")
	account := models.Account{
		Token: tokenString,
	}
	resp["account"] = account
	u.Respond(w, resp)
}

// GetTokens устанавливает токены для определенного пользователя
func SetTokens(w http.ResponseWriter, r *http.Request) {
	// Читаем тело запроса
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		u.Respond(w, u.Message(false, "Error reading request"))
		return
	}

	// Восстанавливаем тело запроса из
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// Универсальный запрос
	baseHttpRequest := BaseHttpRequest{}

	// Анмаршалинг json в структуру
	err = json.NewDecoder(r.Body).Decode(&baseHttpRequest)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}

	// Откидывание пустых токенов сразу
	if strings.TrimSpace(baseHttpRequest.Account.SecretKey) == "" || strings.TrimSpace(baseHttpRequest.Account.APIKey) == "" {
		u.Respond(w, u.Message(false, "Invalid request: SecretKey or APIKey is empty"))
		return
	}

	// Получение ключа подписи из переменных среды
	hashPassword := os.Getenv("hash_password")
	if hashPassword == "" {
		log.Println("Error: hash_password environment variable is not set")
		u.Respond(w, u.Message(false, "Internal erro"))
		return
	}

	// Шифрование токена с помощью ключа
	secretKey, err := u.EncryptToken(baseHttpRequest.Account.SecretKey, hashPassword)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}
	// Шифрование токена с помощью ключа
	apiKey, err := u.EncryptToken(baseHttpRequest.Account.APIKey, hashPassword)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Получение id пользователя из контеста. Контекст установлен в запрос ранее на этапе валидации токена.
	userID, ok := r.Context().Value("user").(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}

	// Установка токенов для пользователя
	err = models.SetTokens(userID, apiKey, secretKey)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}

	resp := u.Message(true, "Tokens have been successfully installed")
	u.Respond(w, resp)
}

// GetTokens возвращает biance токены пользователя.
func GetTokens(w http.ResponseWriter, r *http.Request) {
	// Получение id пользователя из контеста. Контекст установлен в запрос ранее на этапе валидации токена.
	userID, ok := r.Context().Value("user").(uint)
	if !ok || userID == 0 {
		log.Printf("Error: Invalid userID in context: %v", userID)
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}

	apiKey, secretKey, err := models.GetTokens(userID)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Создание мапы
	resp := u.Message(true, "tokens have been successfully received")

	// Добавление в мапу пользователя
	resp["account"] = models.Account{
		APIKey:    apiKey,
		SecretKey: secretKey,
	}
	// Добавление в тело ответа json
	u.Respond(w, resp)
}
