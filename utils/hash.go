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

// 1
const (
	keyLen   = 32 // Длина ключа AES-256
	saltLen  = 32 // Длина соли для scrypt
	nonceLen = 12 // Длина nonce для GCM
	scryptN  = 32768
	scryptR  = 8
	scryptP  = 1
)

// Генерация ключа на основе пароля и соли
func deriveKey(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLen)
}

// Шифрование токена
func EncryptToken(token string, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(token), nil)

	// Объединяем соль, nonce и шифротекст
	encrypted := make([]byte, saltLen+nonceLen+len(ciphertext))
	copy(encrypted[:saltLen], salt)
	copy(encrypted[saltLen:saltLen+nonceLen], nonce)
	copy(encrypted[saltLen+nonceLen:], ciphertext)

	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// Дешифрование токена
func DcryptToken(encryptedToken string, password string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(encryptedToken)
	if err != nil {
		return "", err
	}

	if len(decoded) < saltLen+nonceLen {
		return "", errors.New("некорректный формат зашифрованного токена")
	}

	salt := decoded[:saltLen]
	nonce := decoded[saltLen : saltLen+nonceLen]
	ciphertext := decoded[saltLen+nonceLen:]

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
