package models

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Структуру из библиотеки для использования БД
var db *gorm.DB

// init выполняет подключение к БД по данным пользователя из окружения.
func init() {

	// Загрузка файла .env
	e := godotenv.Load()
	if e != nil {
		fmt.Print(e)
	}
	// Поиск переменных среды
	username := os.Getenv("db_user")
	password := os.Getenv("db_pass")
	dbName := os.Getenv("db_name")
	dbHost := os.Getenv("db_host")
	dbPort := os.Getenv("db_port")

	// Стандартная строка для подключения к БД postgresql
	dbUri := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", username, password, dbHost, dbPort, dbName)
	fmt.Println(dbUri)

	// Сохранение "Подключения" в переменную
	conn, err := gorm.Open(postgres.Open(dbUri), &gorm.Config{})
	if err != nil {
		fmt.Print(err)
	}

	// "Подключение" сохраняется в глобальную переменную
	db = conn

	// Миграция структур в таблицы в БД, если их там не было.
	db.Debug().AutoMigrate(&Account{})
}

// Т.к. db локальная переменные, для передачи во внешние пакеты используется геттер.
func GetDB() *gorm.DB {
	return db
}
