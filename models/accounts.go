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
	jwt.StandardClaims
}

// var CachedAccounts *cache.Cache

// Структура для миграции данных пользователя в БД
type Account struct {
	gorm.Model
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"`
	APIKey    string `json:"api_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Token     string `json:"token,omitempty" sql:"-"`
}

// Validate проверяет можно ли создать аккаунт с такими почтой и паролем
func (account *Account) Validate() (map[string]interface{}, bool) {

	// Проверка электронной почты
	isValid, msg := u.ValidateEmail(account.Email)
	if !isValid {
		return u.Message(false, msg), false
	}

	// Проверка пароля
	isValid, msg = u.ValidatePassword(account.Password)
	if !isValid {
		return u.Message(false, msg), false
	}

	// Создание пустой структуруы, чтобы gorm понял к какой таблице обращаться
	temp := &Account{}

	// Проверка на дубликаты почты
	err := GetDB().Table("accounts").Where("email = ?", account.Email).First(temp).Error
	// Проверка на ошибку при запросе БД
	if err != nil {
		// Если получена ошибка отсутствия такой почты в БД, то отлично
		if strings.Contains(err.Error(), "record not found") {
			return u.Message(true, "Requirement passed"), true
		}
		// Другие ошибки
		return u.Message(false, "Connection error. Please retry"), false
	}

	// Если err == nil, значит запись найдена
	return u.Message(false, "Email address already in use by another user."), false
}

// Create создает аккаунт в БД и возвращает map'у с пользователем и токеном.
func (account *Account) Create() map[string]interface{} {

	// Проверка логина/пароля перед процессом создания
	if resp, ok := account.Validate(); !ok {
		return resp
	}

	// Хеширование пароля стандартной библиотекой. Сложность хеширования по-умолчанию 10. Пароль предворительно переведн в массив байт.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	// Установка пароля в поле структуры
	account.Password = string(hashedPassword)

	// Создание в БД аккаунта с таким паролем.
	GetDB().Create(account)

	// Если ID аккаунту <=0, кидаем ошибку
	if account.ID <= 0 {
		return u.Message(false, "Failed to create account, connection error.")
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
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))

	// Добавления токена в структуру пользователя
	account.Token = tokenString

	// Т.к. структура будет отправлена ответным HHTP, нужно удалить пароль из структуры. Кешированный пароль останится в БД.
	account.Password = "" //delete password

	response := u.Message(true, "Account has been created")
	// Добавление пользователя в map'у
	response["account"] = account

	return response
}

// CreateJWTToken создает jwt токен для данных пользователя
func (account *Account) CreateJWTToken() (string, bool) {

	// Проверка логина/пароля перед процессом создания
	if _, ok := account.Validate(); !ok {
		return "", false
	}

	// Хеширование пароля стандартной библиотекой. Сложность хеширования по-умолчанию 10. Пароль предворительно переведн в массив байт.
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	// Установка пароля в поле структуры
	account.Password = string(hashedPassword)

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
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))

	return tokenString, true
}

// Login выполняет авторизацию пользователя
func Login(email, password string) map[string]interface{} {
	// Создание сруктуру для последующего извлечения и поиска в БД
	account := &Account{}
	// Извлечение пользоваотеля по его почте
	err := GetDB().Table("accounts").Where("email = ?", email).First(account).Error
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
		return "", "", fmt.Errorf("User not found")
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
