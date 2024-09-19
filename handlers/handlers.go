package handlers

import (
	"app/models"
	"app/smtp"
	u "app/utils"
	"bytes"
	"encoding/json"
	"fmt"
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
	Key     string         `json:"key"`
}

// NewUser создание пользователя. Добавление почты в кеш, отправка сообщения, ожидание авторизации.
func NewUser(w http.ResponseWriter, r *http.Request) {
	log.Println("Начало выполнения NewUser")

	// Читаем тело запроса
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Ошибка чтения тела запроса: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Выводим тело запроса
	log.Printf("Тело запроса: %s", string(bodyBytes))

	// Восстанавливаем тело запроса
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	baseHttpRequest := &BaseHttpRequest{}
	err = json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		log.Printf("Ошибка декодирования тела запроса: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	log.Printf("Полученный запрос: %+v", baseHttpRequest)

	// Проверка логина/пароля перед процессом создания
	if resp, ok := baseHttpRequest.Account.Validate(); !ok {
		log.Printf("Ошибка валидации аккаунта: %v", resp)
		u.Respond(w, u.Message(false, "Invalid login credentials. Please try again"))
		return
	}
	log.Println("Валидация аккаунта прошла успешно")

	token, ok := baseHttpRequest.Account.CreateJWTToken()
	if !ok {
		log.Println("Не удалось создать JWT токен")
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	log.Printf("Создан JWT токен: %s", token)
	baseHttpRequest.Account.Token = token

	fmt.Println("TEST: ", baseHttpRequest)
	err = smtp.MailManager.ValidateEmail(&baseHttpRequest.Account)
	if err != nil {
		log.Printf("Ошибка при валидации email: %v", err)
		u.Respond(w, u.Message(false, "Error validating email"))
		return
	}
	log.Println("Email успешно отправлен для валидации")

	resp := u.Message(true, "The account has been successfully added for verification")
	resp["account"] = baseHttpRequest.Account.Token
	log.Printf("Отправляемый ответ: %+v", resp)
	u.Respond(w, resp)
}

func NewValidate(w http.ResponseWriter, r *http.Request) {
	log.Println("Начало выполнения NewValidate")

	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		log.Printf("Ошибка декодирования тела запроса: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	log.Printf("Полученный запрос: %+v", baseHttpRequest)

	token, err := u.GetHeaderToken(r)
	if err != nil {
		log.Printf("Ошибка получения токена из заголовка: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	log.Printf("Полученный токен: %s", token)

	account, err := smtp.MailManager.CheckKey(&baseHttpRequest.Account, baseHttpRequest.Key)
	if err != nil {
		log.Printf("Ошибка проверки ключа: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	log.Printf("Проверка ключа успешна, аккаунт: %+v", account)

	resp := account.Create()
	if !resp["status"].(bool) {
		log.Printf("Ошибка создания аккаунта: %v", resp["message"])
		u.Respond(w, resp)
		return
	}

	smtp.MailManager.DeleteUser(account.Token)
	log.Println("Пользователь удален из кэша")

	log.Println("Аккаунт успешно создан в базе данных")

	u.Respond(w, u.Message(true, "The account has been successfully created"))
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Проверка логина/пароля перед процессом создания
	if resp, ok := baseHttpRequest.Account.Validate(); !ok {
		log.Printf("Ошибка валидации аккаунта: %+v", resp)
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
	smtp.MailManager.ValidateEmail(&baseHttpRequest.Account)

	// Создание мапы
	resp := u.Message(true, "The account has been successfully added for verification")
	// Добавление аккаунта
	resp["account"] = baseHttpRequest.Account.Token
	u.Respond(w, resp)
}

func ValidatePassword(w http.ResponseWriter, r *http.Request) {
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	token, err := u.GetHeaderToken(r)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Проверяет корректность пользователя в бд, получаем аккаунт
	account, isAuthorize := smtp.MailManager.CheckAuthorized(token)
	if !isAuthorize {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Получаем данные в БД
	accountDB := models.GetUserViaEmail(account.Email)
	if accountDB == nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	// Переписываем пароль
	accountDB.Password = account.Password

	// Обновляем пароль в БД
	models.UpdateAllFields(accountDB)

	// Создание мапы
	resp := u.Message(true, "The account has been successfully update")
	u.Respond(w, resp)
}

func SetPassword(w http.ResponseWriter, r *http.Request) {
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	token, err := u.GetHeaderToken(r)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	baseHttpRequest.Account.Token = token

	account, err := smtp.MailManager.CheckKey(&baseHttpRequest.Account, baseHttpRequest.Key)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	account.Create()

	// Создание мапы
	resp := u.Message(true, "The account has been successfully created")
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
	log.Println("Начало выполнения SetTokens")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Ошибка чтения тела запроса: %v", err)
		u.Respond(w, u.Message(false, "Error reading request"))
		return
	}
	log.Printf("Тело запроса: %s", string(body))

	r.Body = io.NopCloser(bytes.NewBuffer(body))

	baseHttpRequest := BaseHttpRequest{}
	err = json.NewDecoder(r.Body).Decode(&baseHttpRequest)
	if err != nil {
		log.Printf("Ошибка декодирования тела запроса: %v", err)
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}
	log.Printf("Декодированный запрос: %+v", baseHttpRequest)

	if strings.TrimSpace(baseHttpRequest.Account.SecretKey) == "" || strings.TrimSpace(baseHttpRequest.Account.APIKey) == "" {
		log.Println("Пустой SecretKey или APIKey")
		u.Respond(w, u.Message(false, "Invalid request: SecretKey or APIKey is empty"))
		return
	}

	hashPassword := os.Getenv("hash_password")
	if hashPassword == "" {
		log.Println("Отсутствует переменная окружения hash_password")
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	secretKey, err := u.EncryptToken(baseHttpRequest.Account.SecretKey, hashPassword)
	if err != nil {
		log.Printf("Ошибка шифрования SecretKey: %v", err)
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}
	log.Println("SecretKey успешно зашифрован")

	apiKey, err := u.EncryptToken(baseHttpRequest.Account.APIKey, hashPassword)
	if err != nil {
		log.Printf("Ошибка шифрования APIKey: %v", err)
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}
	log.Println("APIKey успешно зашифрован")

	userID, ok := r.Context().Value("user").(uint)
	if !ok || userID == 0 {
		log.Printf("Некорректный userID в контексте: %v", userID)
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}
	log.Printf("UserID из контекста: %d", userID)

	err = models.SetTokens(userID, apiKey, secretKey)
	if err != nil {
		log.Printf("Ошибка установки токенов: %v", err)
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}
	log.Println("Токены успешно установлены")

	resp := u.Message(true, "Tokens have been successfully installed")
	log.Printf("Отправляемый ответ: %+v", resp)
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
