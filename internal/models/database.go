package models

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Глобальная переменная для взаимодействия с другими пакетами
var DataBaseManager *DBManager

// Менеджер БД
type DBManager struct {
	db *gorm.DB
}

// init выполняет подключение к БД по данным пользователя из окружения.
func NewDBManager() (*DBManager, error) {
	username := os.Getenv("db_user")
	if username == "" {
		return nil, fmt.Errorf("db_user is empty")
	}

	password := os.Getenv("db_pass")
	if password == "" {
		return nil, fmt.Errorf("db_pass is empty")
	}

	dbName := os.Getenv("db_name")
	if dbName == "" {
		return nil, fmt.Errorf("db_name is empty")
	}

	dbHost := os.Getenv("db_host")
	if dbHost == "" {
		return nil, fmt.Errorf("db_host is empty")
	}

	dbPort := os.Getenv("db_port")
	if dbPort == "" {
		return nil, fmt.Errorf("db_port is empty")
	}

	// Стандартная строка для подключения к БД postgresql
	dbUri := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", username, password, dbHost, dbPort, dbName)
	fmt.Println(dbUri)

	// Сохранение "Подключения" в переменную
	conn, err := gorm.Open(postgres.Open(dbUri), &gorm.Config{})
	if err != nil {
		fmt.Print(err)
	}

	// Миграция структур в таблицы в БД, если их там не было.
	// db.Debug().AutoMigrate(&Account{})

	// "Подключение" сохраняется в глобальную переменную
	return &DBManager{conn}, nil
}
