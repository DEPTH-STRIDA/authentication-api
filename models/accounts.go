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
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"`
	APIKey    string `json:"api_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Token     string `json:"token,omitempty"`
}

func (Account) TableName() string {
	return "accounts"
}

// Validate проверяет корректность пароля и почты, роверяет занята ли почта.
func (account *Account) Validate() error {

	// Проверка электронной почты
	isValid, msg := u.ValidateEmail(account.Email)
	if !isValid {
		return fmt.Errorf("invalid email: %s", msg)
	}

	// Проверка пароля
	isValid, msg = u.ValidatePassword(account.Password)
	if !isValid {
		return fmt.Errorf("invalid password: %s", msg)
	}

	temp := &Account{}

	// Проверка на дубликаты почты
	err := DataBaseManager.db.Table("accounts").Where("email = ?", account.Email).First(temp).Error
	// Проверка на ошибку при запросе БД
	if err != nil {
		// Если получена ошибка отсутствия такой почты в БД, то отлично
		if strings.Contains(err.Error(), "record not found") {
			return nil
		}
		// Другие ошибки
		return fmt.Errorf("connection error. Please retry: %e", err)
	}

	// Если err == nil, значит запись найдена
	return fmt.Errorf("email address already in use by another user.")
}

// Create создает аккаунт в БД и возвращает map'у с пользователем и токеном.
func (account *Account) Create() (string, error) {

	if err := account.Validate(); err != nil {
		return "", err
	}

	hashedPassword, err := HashString(account.Password)
	if err != nil {
		return "", err
	}

	hashedEmail, err := HashString(account.Password)
	if err != nil {
		return "", err
	}

	// Установка пароля в поле структуры
	account.Password = string(hashedPassword)

	// Создание в БД аккаунта с таким паролем.
	result := DataBaseManager.db.Create(account)
	if result.Error != nil {
		return "", fmt.Errorf("failed to create account, database error: ", result.Error)
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

// Login выполняет авторизацию пользователя
func Login(email, password string) (string, error) {
	// Создание сруктуру для последующего извлечения и поиска в БД
	account := &Account{}
	// Извлечение пользоваотеля по его почте
	err := DataBaseManager.db.Table("accounts").Where("email = ?", email).First(account).Error
	if err != nil {
		// Если аккаунт не найден.
		if err == gorm.ErrRecordNotFound {
			return u.Message(false, "Invalid login credentials. Please try again") // Кидаем ошибку авторизации без пояснения в чем ошибка.
		}
		// Другая ошибка БД
		return u.Message(false, "Connection error. Please retry")
	}

	// Хеширования пароля для проверки хешей пароля, полученногоиз бд, и пароля из БД
	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))

	// Пароль не подходит.
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		return u.Message(false, "Invalid login credentials. Please try again") // Кидаем ошибку авторизации без пояснения в чем ошибка.
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

	account.Token = tokenString

	resp := u.Message(true, "Logged In")
	resp["account"] = account
	return resp
}

// GetUser возвращает пользователя из БД по ID
func GetUser(u uint) *Account {

	acc := &Account{}
	GetDB().Table("accounts").Where("id = ?", u).First(acc)
	if acc.Email == "" { //User not found!
		return nil
	}

	acc.Password = ""
	return acc
}

// GetUser возвращает пользователя из БД по почте
func GetUserViaEmail(email string) *Account {

	acc := &Account{}
	GetDB().Table("accounts").Where("email = ?", email).First(acc)
	if acc.Email == "" { //User not found!
		return nil
	}

	acc.Password = ""
	return acc
}

// UpdateAllFields обновляет все поля пользователя
func UpdateAllFields(updatedAccount *Account) error {
	// Получаем текущего пользователя из базы данных
	existingAccount := &Account{}
	err := GetDB().First(existingAccount, updatedAccount.ID).Error
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return fmt.Errorf("user not found : %v", err)
		}
		return fmt.Errorf("connection error. Please retry: %v", err)
	}

	// Обновляем все поля
	err = GetDB().Model(&Account{}).Where("id = ?", updatedAccount.ID).Updates(updatedAccount).Error
	if err != nil {
		return fmt.Errorf("failed to update account. Please retry: %v", err)
	}

	return nil
}

// GetTokens Возвращает два токена. api key, secter key
func GetTokens(userID uint) (apiKey string, SecretKey string, err error) {
	// Получение аккаунта из БД по id
	account := GetUser(userID)
	if account == nil {
		return "", "", fmt.Errorf("user not found")
	}

	return account.APIKey, account.SecretKey, nil
}

func SetTokens(userID uint, apiKey, secretKey string) error {
	// Получение пользователя из БД по id
	account := GetUser(userID)
	if account == nil {
		return fmt.Errorf("user not found")
	}

	// Установка в структуру новых токенов
	account.SecretKey = secretKey
	account.APIKey = apiKey

	// Обновление всех полей по id в БД
	err := UpdateAllFields(account)
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
