package main

import (
	h "app/internal/handler"
	"app/internal/logger"
	"app/internal/models"
	"app/internal/smtp"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	var err error

	// Загружаем .env файл
	err = godotenv.Load()
	if err != nil {
		log.Fatal("Ошибка загрузки .env файла: ", err)
	}

	logger.Log, err = logger.NewLogger()
	if err != nil {
		panic(err)
	}

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

	smtp.MailManager, err = smtp.NewSmtpManager()
	handlerError(err)

	models.DataBaseManager, err = models.NewDBManager()
	handlerError(err)

	port := os.Getenv("port")
	if port == "" {
		port = "8000"
	}

	host := os.Getenv("host")
	if host == "" {
		host = "localhost"
	}

	logger.Log.Info("Запуск сервера по адрессу: ", host+":"+port)
	err = http.ListenAndServe(host+":"+port, router)
	handlerError(err)
}

func handlerError(err error) {
	if err != nil {
		logger.Log.Error(err)
		panic(err)
	}
}
