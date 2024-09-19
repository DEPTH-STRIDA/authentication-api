package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// Определение констант для криптографических операций
const (
	keyLen   = 32    // Длина ключа в байтах для AES-256 (256 бит = 32 байта)
	saltLen  = 32    // Длина соли в байтах для функции scrypt
	nonceLen = 12    // Длина nonce в байтах для режима GCM (Galois/Counter Mode)
	scryptN  = 32768 // Параметр N для scrypt (степень параллелизма)
	scryptR  = 8     // Параметр r для scrypt (размер блока)
	scryptP  = 1     // Параметр p для scrypt (степень параллелизма)
)

// deriveKey генерирует ключ на основе пароля и соли
// Использует алгоритм scrypt для получения ключа из пароля
func deriveKey(password []byte, salt []byte) ([]byte, error) {
	// scrypt.Key генерирует ключ заданной длины (keyLen)
	// используя предоставленные параметры N, r, p
	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLen)
}

// EncryptToken шифрует токен с использованием предоставленного пароля
func EncryptToken(token string, password string) (string, error) {
	// Генерация случайной соли
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err // Возвращаем ошибку, если не удалось сгенерировать соль
	}

	// Получение ключа шифрования на основе пароля и соли
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось получить ключ
	}

	// Создание нового шифра AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось создать шифр
	}

	// Создание GCM (Galois/Counter Mode) для AES
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось создать GCM
	}

	// Генерация случайного nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err // Возвращаем ошибку, если не удалось сгенерировать nonce
	}

	// Шифрование токена
	ciphertext := gcm.Seal(nil, nonce, []byte(token), nil)

	// Объединение соли, nonce и шифротекста в одну последовательность байтов
	encrypted := make([]byte, saltLen+nonceLen+len(ciphertext))
	copy(encrypted[:saltLen], salt)                  // Копирование соли
	copy(encrypted[saltLen:saltLen+nonceLen], nonce) // Копирование nonce
	copy(encrypted[saltLen+nonceLen:], ciphertext)   // Копирование шифротекста

	// Кодирование результата в base64 и возврат
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// DcryptToken расшифровывает зашифрованный токен с использованием предоставленного пароля
func DcryptToken(encryptedToken string, password string) (string, error) {
	// Декодирование зашифрованного токена из base64
	decoded, err := base64.URLEncoding.DecodeString(encryptedToken)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось декодировать токен
	}

	// Проверка, что длина декодированного токена достаточна для извлечения соли и nonce
	if len(decoded) < saltLen+nonceLen {
		return "", errors.New("некорректный формат зашифрованного токена")
	}

	// Извлечение соли, nonce и шифротекста из декодированных данных
	salt := decoded[:saltLen]
	nonce := decoded[saltLen : saltLen+nonceLen]
	ciphertext := decoded[saltLen+nonceLen:]

	// Получение ключа расшифрования на основе пароля и извлеченной соли
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось получить ключ
	}

	// Создание нового шифра AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось создать шифр
	}

	// Создание GCM (Galois/Counter Mode) для AES
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось создать GCM
	}

	// Расшифровка токена
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err // Возвращаем ошибку, если не удалось расшифровать токен
	}

	// Возвращаем расшифрованный токен в виде строки
	return string(plaintext), nil
}
