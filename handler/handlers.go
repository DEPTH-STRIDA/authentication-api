package handler

import (
	"app/models"
	"app/smtp"
	u "app/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// NewUser создание пользователя. Добавление почты в кеш, отправка сообщения, ожидание авторизации.
func NewUser(w http.ResponseWriter, r *http.Request) {
	// Парсинг тела запроса
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	fmt.Println(baseHttpRequest)
	// Проверка логина/пароля перед процессом создания
	if err := baseHttpRequest.Account.Validate(); err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		return
	}

	// Отправка кода на почту/добавление в кеш
	token, err := smtp.MailManager.ValidateEmail(baseHttpRequest.Account)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Создаем структуру для ответа
	resp := u.Message(true, "The account has been successfully added for verification")

	// Добавление в ответ "пользователя" с токеном
	resp["account"] = models.Account{Token: token}

	u.Respond(w, resp)
}

// NewValidate проверяет аккаунт и создает его, если ключ и токен верные.
func NewValidate(w http.ResponseWriter, r *http.Request) {
	// Извлеченеи токена
	token, ok := r.Context().Value(TokenCtx).(string)
	if !ok || token == "" {
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}

	// Парсинг тела запроса
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request: invalid body"))
		return
	}

	// Извлечение токена

	// Замена токена в случае правильного ключа
	newToken, err := smtp.MailManager.CheckKey(token, baseHttpRequest.Key)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		return
	}

	// Возврат авторизованного аккаунта
	newAccount, ok := smtp.MailManager.CheckStatus(newToken)
	if !ok {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Создание аккаунта в БД
	_, err = newAccount.Create()
	if err != nil {
		return
	}

	// Если нет ошибок в БД, то удаляем из кеша
	smtp.MailManager.Delete(token)

	u.Respond(w, u.Message(true, "The account has been successfully created"))
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Парсинг тела запроса
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Проверка электронной почты
	err = u.ValidateEmail(baseHttpRequest.Account.Email)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		return
	}

	_, err = models.GetUserViaEmail(baseHttpRequest.Account.Email)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		return
	}

	// Начать процесс восстановления почты
	token, err := smtp.MailManager.ValidateEmail(baseHttpRequest.Account)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "The account has been successfully added for verification")

	// Добавление в ответ "пользователя" с токеном
	resp["account"] = models.Account{Token: token}

	u.Respond(w, resp)
}

func ValidatePassword(w http.ResponseWriter, r *http.Request) {
	// Извлеченеи токена
	token, ok := r.Context().Value(TokenCtx).(string)
	if !ok || token == "" {
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Проверяет корректность пользователя в бд, получаем аккаунт
	newToken, err := smtp.MailManager.CheckKey(token, baseHttpRequest.Key)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "The account has been successfully update")
	// Добавление пользователя с новым токеном
	resp["account"] = models.Account{Token: newToken}

	u.Respond(w, resp)
}

func SetPassword(w http.ResponseWriter, r *http.Request) {
	// Извлеченеи токена
	token, ok := r.Context().Value(TokenCtx).(string)
	if !ok || token == "" {
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	err = u.ValidatePassword(baseHttpRequest.Account.Password)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid password"))
		return
	}

	// Проверка статуса аккунта
	account, ok := smtp.MailManager.CheckStatus(token)
	if !ok {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Получение аккаунт из БД по почте
	accountDB, err := models.GetUserViaEmail(account.Email)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	// Хеширование пароля
	hashedPassword, err := models.HashString(baseHttpRequest.Account.Password)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}
	// Установка нового хеша пароля
	accountDB.Password = hashedPassword

	// Обновление всех полей, кроме ID
	err = models.UpdateAllFieldsAccount(accountDB)
	if err != nil {
		fmt.Println(err)
		resp := u.Message(false, "Internal error")
		u.Respond(w, resp)
	}

	// Создание мапы
	resp := u.Message(true, "The account has been successfully created")

	u.Respond(w, resp)
}

// Authenticate авторизация на сайте
func Login(w http.ResponseWriter, r *http.Request) {
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	token, err := models.Login(baseHttpRequest.Account.Email, baseHttpRequest.Account.Password)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		return
	}

	// Осздание ответной структуры
	resp := u.Message(true, "Succes")
	// Занесение аккаунта с токенов в структуру
	resp["account"] = models.Account{Token: token}

	u.Respond(w, resp)
}

// RefreshJWTToken генерирует новый рабочий JWT токен
func RefreshJWTToken(w http.ResponseWriter, r *http.Request) {
	// Извлечение ID из контекста
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}

	// Генерация нового токена
	newToken := models.Token{
		UserId: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		},
	}

	//Шифррование и подпись токена
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, newToken).SignedString([]byte(os.Getenv("token_password")))
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "tokens have been successfully updated")

	// Добавление аккаунта с токеном в ответную структуру
	resp["account"] = models.Account{Token: tokenString}

	u.Respond(w, resp)
}

// GetTokens устанавливает токены для определенного пользователя
func SetTokens(w http.ResponseWriter, r *http.Request) {
	// Извлечение ID из контекста
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}

	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}
	// Проверка ключей
	if strings.TrimSpace(baseHttpRequest.Account.SecretKey) == "" || strings.TrimSpace(baseHttpRequest.Account.APIKey) == "" {
		u.Respond(w, u.Message(false, "Invalid request: SecretKey or APIKey is empty"))
		return
	}

	// Получение подписи токенов
	hashPassword := os.Getenv("hash_password")
	if hashPassword == "" {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Шифрование токенов
	secretKey, err := u.EncryptToken(baseHttpRequest.Account.SecretKey, hashPassword)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}
	apiKey, err := u.EncryptToken(baseHttpRequest.Account.APIKey, hashPassword)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Установка токенов в БД
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
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}

	apiKey, secretKey, err := models.GetTokens(userID)
	if err != nil {
		u.Respond(w, u.Message(false, "Internal error"))
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "tokens have been successfully received")

	// Добавление в ответную структуру пользователя с ключами
	resp["account"] = models.Account{APIKey: apiKey, SecretKey: secretKey}

	u.Respond(w, resp)
}
