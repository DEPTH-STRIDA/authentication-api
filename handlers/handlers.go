package handlers

import (
	"app/models"
	"app/smtp"
	u "app/utils"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// NewUser создание пользователя. Добавление почты в кеш, отправка сообщения, ожидание авторизации.
func NewUser(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting CreateAccount handler")

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

// NewValidate проверка кода по токену в кеше. В случае успеха создает пользователя.
func NewValidate(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting CreateAccount handler")

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

func Authenticate(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting Authenticate handler")

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	resp := models.Login(account.Email, account.Password)
	log.Printf("Authentication response: %+v", resp)

	u.Respond(w, resp)
}

func SetTokens(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting SetTokens handler")

	// Читаем тело запроса
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		u.Respond(w, u.Message(false, "Error reading request"))
		return
	}
	log.Printf("Received request body: %s", string(body))

	// Восстанавливаем тело запроса
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	var requestData struct {
		APIKey    string `json:"api_key"`
		SecretKey string `json:"secret_key"`
	}

	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		u.Respond(w, u.Message(false, "Invalid request format"))
		return
	}

	log.Printf("Decoded request data: %+v", requestData)

	if requestData.SecretKey == "" || requestData.APIKey == "" {
		log.Println("Error: SecretKey or APIKey is empty")
		u.Respond(w, u.Message(false, "Invalid request: SecretKey or APIKey is empty"))
		return
	}

	userID, ok := r.Context().Value("user").(uint)
	if !ok || userID == 0 {
		log.Printf("Error: Invalid userID in context: %v", userID)
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}

	accountBD := models.GetUser(userID)
	if accountBD == nil {
		log.Printf("Error: User not found for ID: %d", userID)
		u.Respond(w, u.Message(false, "User not found"))
		return
	}

	hashPassword := os.Getenv("hash_password")
	if hashPassword == "" {
		log.Println("Error: hash_password environment variable is not set")
		u.Respond(w, u.Message(false, "Internal error: Missing configuration"))
		return
	}

	secretKey, err := u.EncryptToken(requestData.SecretKey, hashPassword)
	if err != nil {
		log.Printf("Error encrypting SecretKey: %v", err)
		u.Respond(w, u.Message(false, "Internal error: Encryption failed"))
		return
	}
	apiKey, err := u.EncryptToken(requestData.APIKey, hashPassword)
	if err != nil {
		log.Printf("Error encrypting APIKey: %v", err)
		u.Respond(w, u.Message(false, "Internal error: Encryption failed"))
		return
	}

	accountBD.SecretKey = secretKey
	accountBD.APIKey = apiKey

	err = models.UpdateAllFields(accountBD)
	if err != nil {
		log.Printf("Error updating user fields: %v", err)
		u.Respond(w, u.Message(false, "Failed to update user data"))
		return
	}

	log.Println("Tokens successfully installed")
	resp := u.Message(true, "Tokens have been successfully installed")
	u.Respond(w, resp)
}

func RefreshJWTToken(w http.ResponseWriter, r *http.Request) {
	log.Println("Starting RefreshJWTToken handler")

	tokenHeader := r.Header.Get("Authorization")
	splitted := strings.Split(tokenHeader, " ")
	if len(splitted) != 2 {
		log.Println("Error: Invalid Authorization header format")
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	tokenPart := splitted[1]
	tk := &models.Token{}

	_, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("token_password")), nil
	})
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		u.Respond(w, u.Message(false, "Invalid request"))
		return
	}

	timeUntilExpiration := time.Until(time.Unix(tk.ExpiresAt, 0))
	log.Printf("Time until token expiration: %v", timeUntilExpiration)

	if timeUntilExpiration < 5*time.Minute && timeUntilExpiration > 0 {
		newToken := models.Token{
			UserId: tk.UserId,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			},
		}
		tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, newToken).SignedString([]byte(os.Getenv("token_password")))
		if err != nil {
			log.Printf("Error creating new token: %v", err)
			u.Respond(w, u.Message(false, "Internal error"))
			return
		}

		log.Println("Token successfully refreshed")
		resp := u.Message(true, "tokens have been successfully updated")
		resp["token"] = tokenString
		u.Respond(w, resp)
	} else {
		log.Println("Token refresh not needed")
		u.Respond(w, u.Message(false, "Invalid request"))
	}
}

func GetTokens(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("user").(uint)
	if !ok || userID == 0 {
		log.Printf("Error: Invalid userID in context: %v", userID)
		u.Respond(w, u.Message(false, "Internal error: Invalid user identification"))
		return
	}

	accountBD := models.GetUser(userID)
	if accountBD == nil {
		log.Printf("Error: User not found for ID: %d", userID)
		u.Respond(w, u.Message(false, "User not found"))
		return
	}

	accounToSend := models.Account{
		APIKey:    accountBD.APIKey,
		SecretKey: accountBD.SecretKey,
	}

	log.Println("Tokens successfully installed")
	resp := u.Message(true, "tokens have been successfully received")
	resp["account"] = accounToSend

	u.Respond(w, resp)
}
