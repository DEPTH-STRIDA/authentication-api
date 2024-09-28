package main

import (
	h "app/handler"
	"app/models"
	"app/smtp"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	router := mux.NewRouter()

	// Новый аккаунт
	router.HandleFunc("/api/user/new", h.NewUser).Methods("POST")
	router.HandleFunc("/api/user/new/validate", h.TokenValidation(h.NewValidate)).Methods("POST")

	// Сброс пароля
	router.HandleFunc("/api/user/password/reset", h.ResetPassword).Methods("POST")
	router.HandleFunc("/api/user/password/validate", h.TokenValidation(h.ValidatePassword)).Methods("POST")
	router.HandleFunc("/api/user/password/set", h.TokenValidation(h.SetPassword)).Methods("POST")

	// Авторизация-обновление
	router.HandleFunc("/api/user/login", h.Login).Methods("POST")
	router.HandleFunc("/api/user/refresh", h.JwtAuthentication(h.RefreshJWTToken)).Methods("POST")

	// Работа с токенами
	router.HandleFunc("/api/user/set-tokens", h.JwtAuthentication(h.SetTokens)).Methods("POST")
	router.HandleFunc("/api/user/get-tokens", h.JwtAuthentication(h.GetTokens)).Methods("POST")

	// Временное
	router.HandleFunc("/api/internal/get-user-id", h.JwtAuthentication(h.GetUserId)).Methods("POST")

	// Загрузка файла .env
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	smtp.MailManager, err = smtp.NewSmtpManager()
	if err != nil {
		panic(err)
	}

	models.DataBaseManager, err = models.NewDBManager()
	if err != nil {
		panic(err)
	}

	port := os.Getenv("port")
	if port == "" {
		port = "8000"
	}

	host := os.Getenv("host")
	if host == "" {
		host = "localhost"
	}

	err = http.ListenAndServe(host+":"+port, router)
	if err != nil {
		panic(err)
	}
}
