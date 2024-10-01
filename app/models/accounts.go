// models хранит структуры и их методы. В частности структуры связанные с БД.
package models

import (
	u "app/utils"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// Структура, которая кодируется в Json и передается вместе с HTTP.
type Token struct {
	UserId uint
	Email  string
	jwt.StandardClaims
}

// Структура для миграции данных пользователя в БД
type Account struct {
	gorm.Model
	Email     string `json:"email" gorm:"column:email"`
	Password  string `json:"password,omitempty" gorm:"column:password"`
	APIKey    string `json:"api_key,omitempty" gorm:"-"`
	SecretKey string `json:"secret_key,omitempty" gorm:"-"`
	Token     string `json:"token,omitempty" gorm:"-"`
}

func (Account) TableName() string {
	return "accounts"
}

type Keys struct {
	gorm.Model
	AccountID       uint   `gorm:"column:account_id"`
	BianceApiKey    string `gorm:"column:biance_api_key"`
	BianceSecretKey string `gorm:"column:biance_secret_key"`
}

func (Keys) TableName() string {
	return "keys"
}

// Validate проверяет корректность пароля и почты, роверяет занята ли почта.
func (account *Account) Validate() error {

	// Проверка электронной почты
	err := u.ValidateEmail(account.Email)
	if err != nil {
		return fmt.Errorf("invalid email: %s", err.Error())
	}

	// Проверка пароля
	err = u.ValidatePassword(account.Password)
	if err != nil {
		return fmt.Errorf("invalid password: %s", err.Error())
	}
	temp := &Account{}

	// Проверка на дубликаты почты
	err = DataBaseManager.db.Table("accounts").Where("email = ?", account.Email).First(temp).Error
	// Проверка на ошибку при запросе БД
	if err != nil {
		// Если получена ошибка отсутствия такой почты в БД, то отлично
		if strings.Contains(err.Error(), "record not found") {
			return nil
		}
		fmt.Println("Ошибка БД")
		// Другие ошибки
		return fmt.Errorf("connection error. Please retry: %e", err)
	}
	// fmt.Println("Почта занята")
	// Если err == nil, значит запись найдена
	return fmt.Errorf("email address already in use by another user")
}

// Create создает аккаунт в БД и возвращает токен пользователя и ошибку
func (account *Account) Create() (string, error) {

	if err := account.Validate(); err != nil {
		return "", err
	}

	hashedPassword, err := HashString(account.Password)
	if err != nil {
		return "", err
	}

	// Установка пароля в поле структуры
	account.Password = string(hashedPassword)

	// Создание в БД аккаунта с таким паролем.
	result := DataBaseManager.db.Create(account)
	if result.Error != nil {
		return "", fmt.Errorf("failed to create account, database error: %s", result.Error)
	}

	// Создание временной метки истечения срока жизни токена ("истекает в")
	expirationTime := time.Now().Add(15 * time.Minute)
	// Структура токен
	tk := &Token{
		UserId: account.ID,
		// Стандартный токен библиотеки JWT, но с временой меткой "Истекает в"
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//Создание токена из структуры "tj" с алгоритмом (HMAC-SHA256) для шифрования токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tk)

	// Подпись токена с помощью уникального ключа из .env
	tokenString, err := token.SignedString([]byte(os.Getenv("token_password")))
	if err != nil {
		return "", fmt.Errorf("failed to generate token")
	}

	return tokenString, nil
}

// CreateJWTToken создает jwt токен для данных пользователя
func (account *Account) CreateJWTToken() (string, error) {
	// Проверка логина/пароля перед процессом создания
	if err := account.Validate(); err != nil {
		return "", err
	}

	// Структура токена
	tk := &Token{
		UserId:         account.ID,
		Email:          account.Email,
		StandardClaims: jwt.StandardClaims{},
	}

	// Создание токена из структуры "tk" с алгоритмом (HMAC-SHA256) для шифрования токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tk)

	// Подпись токена с помощью уникального ключа из .env
	tokenPassword := os.Getenv("token_password")
	if tokenPassword == "" {
		return "", fmt.Errorf("token_password is empty")
	}

	tokenString, err := token.SignedString([]byte(tokenPassword))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Login выполняет авторизацию пользователя. Возвращает токен и ошибку в случае неудачи.
func Login(email, password string) (string, error) {
	// Создание сруктуру для последующего извлечения и поиска в БД
	account := &Account{}
	// Извлечение пользоваотеля по его почте
	err := DataBaseManager.db.Table("accounts").Where("email = ?", email).First(account).Error
	if err != nil {
		// Если аккаунт не найден.
		if err == gorm.ErrRecordNotFound {
			return "", fmt.Errorf("invalid login credentials. Please try again")
		}
		// Другая ошибка БД
		return "", fmt.Errorf("connection error. Please retry")
	}

	// Хеширования пароля для проверки хешей пароля, полученногоиз бд, и пароля из БД
	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))

	// Пароль не подходит.
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return "", fmt.Errorf("invalid login credentials. Please try again")
	}
	// Пароль сработал, но его надо удалить из структуры, она будет передоваться дальше
	account.Password = ""

	// Создание временнной метки "истекает в"
	expirationTime := time.Now().Add(15 * time.Minute)
	// Структура "tk"
	tk := &Token{
		UserId: account.ID,
		// Стандартный токен JWT библиотеки с временной меткой
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Шифрование токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tk)
	// Подпись токена
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))

	return tokenString, nil
}

// GetUser возвращает пользователя из БД по ID
func GetUser(u uint) (*Account, error) {

	acc := &Account{}
	db := DataBaseManager.db.Table("accounts").Where("id = ?", u).First(acc)
	if db.Error != nil || acc.Email == "" {
		return nil, fmt.Errorf("user not found")
	}

	return acc, nil
}

// GetUser возвращает пользователя из БД по почте
func GetUserViaEmail(email string) (*Account, error) {

	acc := &Account{}
	db := DataBaseManager.db.Table("accounts").Where("email = ?", email).First(acc)
	if db.Error != nil || acc.Email == "" {
		return nil, fmt.Errorf("user not found")
	}

	return acc, nil
}

// UpdateAllFields обновляет все поля пользователя. Запись введется по ID
func UpdateAllFieldsAccount(updatedAccount *Account) error {
	// Получаем текущего пользователя из базы данных
	existingAccount := &Account{}
	err := DataBaseManager.db.First(existingAccount, updatedAccount.ID).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return fmt.Errorf("user not found : %v", err)
		}
		return fmt.Errorf("connection error. Please retry: %v", err)
	}

	// Обновляем все поля
	err = DataBaseManager.db.Model(&Account{}).Where("id = ?", updatedAccount.ID).Updates(updatedAccount).Error
	if err != nil {
		return fmt.Errorf("failed to update account. Please retry: %v", err)
	}

	return nil
}

func UpdateAllFieldsKeys(updatedAccount *Keys) error {
	// Получаем текущего пользователя из базы данных
	existingAccount := &Keys{}
	err := DataBaseManager.db.First(existingAccount, updatedAccount.ID).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return fmt.Errorf("user not found : %v", err)
		}
		return fmt.Errorf("connection error. Please retry: %v", err)
	}

	// Обновляем все поля
	err = DataBaseManager.db.Model(&Keys{}).Where("id = ?", updatedAccount.ID).Updates(updatedAccount).Error
	if err != nil {
		return fmt.Errorf("failed to update account. Please retry: %v", err)
	}

	return nil
}

// GetTokens Возвращает два токена. api key, secter key
func GetTokens(userID uint) (apiKey string, SecretKey string, err error) {
	// Получение аккаунта из БД по id
	keys := &Keys{}
	db := DataBaseManager.db.Table("keys").Where("id = ?", userID).First(keys)
	if db.Error != nil {
		return "", "", fmt.Errorf("user not found")
	}

	return keys.BianceApiKey, keys.BianceSecretKey, nil
}

func SetTokens(userID uint, apiKey, secretKey string) error {
	// Получение пользователя из БД по id
	keys := &Keys{}
	db := DataBaseManager.db.Table("keys").Where("id = ?", userID).First(keys)
	if db.Error != nil {
		return fmt.Errorf("user not found")
	}

	keys.BianceApiKey = apiKey
	keys.BianceSecretKey = secretKey

	// Обновление всех полей по id в БД
	err := UpdateAllFieldsKeys(keys)
	if err != nil {
		return err
	}
	return nil
}

// HashString хеширует строку стандартным мехонизмом хеширования паролей.
func HashString(str string) (string, error) {
	// Хеширование пароля стандартной библиотекой. Сложность хеширования по-умолчанию 10. Пароль предворительно переведен в массив байт.
	hashedStr, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedStr), nil
}
