package main

import (
	"app/handlers"
	"app/middleware"
	"fmt"
	"net/http"

	"app/console"

	"github.com/gorilla/mux"
)

func main() {
	// Иницилизация кеша для аккаунтов
	// models.CachedAccounts = cache.New(5*time.Minute, 10*time.Minute)

	// Машрутизатор, который управляет какой обработчик запустить и на какой путь.
	router := mux.NewRouter()

	router.HandleFunc("/api/user/new", handlers.CreateAccount).Methods("POST")
	router.HandleFunc("/api/user/login", handlers.Authenticate).Methods("POST")
	router.HandleFunc("/api/user/set-tokens", handlers.SetTokens).Methods("POST")
	router.HandleFunc("/api/user/refresh", handlers.RefreshJWTToken).Methods("POST")

	/////////////////////////////////////////////////////////////////////////////////
	///////////////////                   TEST                    ///////////////////
	/////////////////////////////////////////////////////////////////////////////////
	router.HandleFunc("/api/user/get-tokens", handlers.GetTokens).Methods("POST")

	// Установка путей для которых не надо проверять токен
	middleware.NotAuth = middleware.NotAuthRoutes{
		Routes: []string{
			"/api/user/new",
			"/api/user/login",
		},
	}
	// Применяем "посредника", который проверяет токен перед работой основного обработчика
	router.Use(middleware.JwtAuthentication)

	//  Если в переменной среды не найдено "PORT", то приложенеие развернется на порту по-умолчанию
	// port := os.Getenv("PORT")
	// if port == "" {
	// 	port = "8000" //localhost
	// }

	port := "8000" //localhost

	// Использование глобальнго логгера
	fmt.Println(port)

	go console.StartUserInterface()

	// Запуск сервера
	err := http.ListenAndServe(":"+port, router)
	// Т.к. сервер должен работать бесконечно, то ошибка будет признаком выключения программы.
	if err != nil {
		fmt.Println(err)
	}
}
