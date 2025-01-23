package handler

import (
	"app/internal/logger"
	"app/internal/models"
	"app/internal/smtp"
	u "app/internal/utils"
	"encoding/json"
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
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при декадировании тела: ", err.Error())
		return
	}

	// Проверка логина/пароля перед процессом создания
	if err := baseHttpRequest.Account.Validate(); err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при валидации данных для входа: ", err.Error())
		return
	}

	// Отправка кода на почту/добавление в кеш
	token, err := smtp.MailManager.ValidateEmail(baseHttpRequest.Account)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при валидации email: ", err.Error())
		return
	}

	// Создаем структуру для ответа
	resp := u.Message(true, "The account has been successfully added for verification")
	w.WriteHeader(http.StatusOK)
	// Добавление в ответ "пользователя" с токеном
	resp["account"] = models.Account{Token: token}

	u.Respond(w, resp)
}

// NewValidate проверяет аккаунт и создает его, если ключ и токен верные.
func NewValidate(w http.ResponseWriter, r *http.Request) {
	// Извлеченеи токена
	token, ok := r.Context().Value(TokenCtx).(string)
	if !ok || token == "" {
		u.Respond(w, u.Message(false, "the token could not be extracted from the cotext"))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста. ")
		return
	}

	// Парсинг тела запроса
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при декадировании тела: ", err.Error())
		return
	}

	// Извлечение токена

	// Замена токена в случае правильного ключа
	newToken, err := smtp.MailManager.CheckKey(token, baseHttpRequest.Key)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при проверка кода с почты: ", err.Error())
		return
	}

	// Возврат авторизованного аккаунта
	newAccount, ok := smtp.MailManager.CheckStatus(newToken)
	if !ok {
		u.Respond(w, u.Message(false, "ошибка при извлечении аккаунта из тела"))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении аккаунта из тела. ")
		return
	}

	// Создание аккаунта в БД
	_, err = newAccount.Create()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при создании аккаунта в БД.")
		return
	}

	// Если нет ошибок в БД, то удаляем из кеша
	smtp.MailManager.Delete(token)
	w.WriteHeader(http.StatusOK)

	u.Respond(w, u.Message(true, "The account has been successfully created"))
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Парсинг тела запроса
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при декадировании тела: ", err.Error())
		return
	}

	// Проверка электронной почты
	err = u.ValidateEmail(baseHttpRequest.Account.Email)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при проверке email: ", err.Error())
		return
	}

	_, err = models.GetUserViaEmail(baseHttpRequest.Account.Email)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении аккаунта ", err.Error())
		return
	}

	// Начать процесс восстановления почты
	token, err := smtp.MailManager.ValidateEmail(baseHttpRequest.Account)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при отправке сообщения на почту ", err.Error())

		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "The account has been successfully added for verification")

	// Добавление в ответ "пользователя" с токеном
	resp["account"] = models.Account{Token: token}
	w.WriteHeader(http.StatusOK)

	u.Respond(w, resp)
}

func ValidatePassword(w http.ResponseWriter, r *http.Request) {
	// Извлеченеи токена
	token, ok := r.Context().Value(TokenCtx).(string)
	if !ok || token == "" {
		u.Respond(w, u.Message(false, "ошибка при извлечении токена из контеста."))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста. ")
		return
	}
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при декадировании тела: ", err.Error())
		return
	}

	// Проверяет корректность пользователя в бд, получаем аккаунт
	newToken, err := smtp.MailManager.CheckKey(token, baseHttpRequest.Key)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при проверке кода с почты: ", err.Error())
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "The account has been successfully update")
	// Добавление пользователя с новым токеном
	resp["account"] = models.Account{Token: newToken}
	w.WriteHeader(http.StatusOK)
	u.Respond(w, resp)
}

func SetPassword(w http.ResponseWriter, r *http.Request) {
	// Извлеченеи токена
	token, ok := r.Context().Value(TokenCtx).(string)
	if !ok || token == "" {
		u.Respond(w, u.Message(false, "ошибка при извлечении токена из контеста."))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста. ")
		return
	}
	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при декадировании тела: ", err.Error())
		return
	}

	err = u.ValidatePassword(baseHttpRequest.Account.Password)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при проверке пароля: ", err.Error())
		return
	}

	// Проверка статуса аккунта
	account, ok := smtp.MailManager.CheckStatus(token)
	if !ok {
		u.Respond(w, u.Message(false, "Не удалось проверить статус аккаунта"))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось проверить статус аккаунта.")
		return
	}

	// Получение аккаунт из БД по почте
	accountDB, err := models.GetUserViaEmail(account.Email)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Ошибка при получении пользователя из БД: ", err.Error())
		return
	}

	// Хеширование пароля
	hashedPassword, err := models.HashString(baseHttpRequest.Account.Password)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Ошибка при хешировании пароля: ", err.Error())
		return
	}
	// Установка нового хеша пароля
	accountDB.Password = hashedPassword

	// Обновление всех полей, кроме ID
	err = models.UpdateAllFieldsAccount(accountDB)
	if err != nil {
		resp := u.Message(false, err.Error())
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Ошибка при обновлении пользователя в БД: ", err.Error())
		u.Respond(w, resp)
	}

	// Создание мапы
	resp := u.Message(true, "The account has been successfully created")
	w.WriteHeader(http.StatusOK)
	u.Respond(w, resp)
}

// Authenticate авторизация на сайте
func Login(w http.ResponseWriter, r *http.Request) {
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Ошибка декодировании тела запроса: ", err.Error())
		return
	}

	token, err := models.Login(baseHttpRequest.Account.Email, baseHttpRequest.Account.Password)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Ошибка авторизации: ", err.Error())
		return
	}

	// Осздание ответной структуры
	resp := u.Message(true, "Succes")
	// Занесение аккаунта с токенов в структуру
	resp["account"] = models.Account{Token: token}
	w.WriteHeader(http.StatusOK)
	u.Respond(w, resp)
}

// RefreshJWTToken генерирует новый рабочий JWT токен
func RefreshJWTToken(w http.ResponseWriter, r *http.Request) {
	// Извлечение ID из контекста
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "ошибка при извлечении токена из контеста."))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста.: ")
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
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при шифровании токена: ", err.Error())
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "tokens have been successfully updated")

	// Добавление аккаунта с токеном в ответную структуру
	resp["account"] = models.Account{Token: tokenString}
	w.WriteHeader(http.StatusOK)
	u.Respond(w, resp)
}

// GetTokens устанавливает токены для определенного пользователя
func SetTokens(w http.ResponseWriter, r *http.Request) {
	// Извлечение ID из контекста
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "ошибка при извлечении токена из контеста."))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста.")
		return
	}

	// Получение данных аккаунта из тела
	baseHttpRequest := &BaseHttpRequest{}
	err := json.NewDecoder(r.Body).Decode(baseHttpRequest)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при декодировании тела: ", err.Error())
		return
	}
	// Проверка ключей
	if strings.TrimSpace(baseHttpRequest.Account.SecretKey) == "" || strings.TrimSpace(baseHttpRequest.Account.APIKey) == "" {
		u.Respond(w, u.Message(false, "Invalid request: SecretKey or APIKey is empty"))
		w.WriteHeader(http.StatusBadRequest)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Invalid request: SecretKey or APIKey is empty.")
		return
	}

	// Получение подписи токенов
	hashPassword := os.Getenv("hash_password")
	if hashPassword == "" {
		u.Respond(w, u.Message(false, "Не удалось получить хеш подписи."))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось получить хеш подписи..")
		return
	}

	// Шифрование токенов
	secretKey, err := u.EncryptToken(baseHttpRequest.Account.SecretKey, hashPassword)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось зашифровать токен: ", err.Error())
		return
	}
	apiKey, err := u.EncryptToken(baseHttpRequest.Account.APIKey, hashPassword)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось зашифровать токен: ", err.Error())
		return
	}

	// Установка токенов в БД
	err = models.SetTokens(userID, apiKey, secretKey)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось установить токен в БД: ", err.Error())
		return
	}

	resp := u.Message(true, "Tokens have been successfully installed")
	w.WriteHeader(http.StatusOK)
	u.Respond(w, resp)
}

// GetTokens возвращает biance токены пользователя.
func GetTokens(w http.ResponseWriter, r *http.Request) {
	// Получение id пользователя из контеста. Контекст установлен в запрос ранее на этапе валидации токена.
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "ошибка при извлечении токена из контеста."))
		w.WriteHeader(http.StatusBadGateway)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста. ")
		return
	}

	apiKey, secretKey, err := models.GetTokens(userID)
	if err != nil {
		u.Respond(w, u.Message(false, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- не удалось извлечь токены из БД: ", err.Error())
		return
	}

	akiKeyDec, err := u.DcryptToken(apiKey, os.Getenv("wXRuiFOyCHQIB58DrBBIe2QHjbwkmSCivBP4puZqYZId"))
	if err != nil {
		u.Respond(w, u.Message(false, "Не удалось дешифровать токены"))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось дешифровать токены: ", err.Error())
		return
	}

	secretKeyDec, err := u.DcryptToken(secretKey, os.Getenv("wXRuiFOyCHQIB58DrBBIe2QHjbwkmSCivBP4puZqYZId"))
	if err != nil {
		u.Respond(w, u.Message(false, "Не удалось дешифровать токены"))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- Не удалось дешифровать токены: ", err.Error())
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "tokens have been successfully received")

	// Добавление в ответную структуру пользователя с ключами
	resp["account"] = models.Account{APIKey: akiKeyDec, SecretKey: secretKeyDec}
	w.WriteHeader(http.StatusOK)
	u.Respond(w, resp)
}

// GetTokens возвращает biance токены пользователя.
func GetUserId(w http.ResponseWriter, r *http.Request) {
	// Получение id пользователя из контеста. Контекст установлен в запрос ранее на этапе валидации токена.
	userID, ok := r.Context().Value(UserIDCtx).(uint)
	if !ok || userID == 0 {
		u.Respond(w, u.Message(false, "ошибка при извлечении токена из контеста."))
		w.WriteHeader(http.StatusInternalServerError)
		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена из контеста.")
		return
	}

	// Создание ответной структуры
	resp := u.Message(true, "tokens have been successfully received")

	// Добавление в ответную структуру пользователя с ключами
	resp["id"] = userID
	w.WriteHeader(http.StatusOK)

	u.Respond(w, resp)
}
