package handler

import (
	"app/internal/logger"
	"app/internal/models"
	u "app/internal/utils"
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

type contextKey string

const (
	UserIDCtx contextKey = "user_id"
	TokenCtx  contextKey = "validation_token"
)

// TokenValidation проверяет наличие и правильность токена из заголовка с подписью "Validation"
func TokenValidation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Извлечение токена
		token, err := u.ExtractToken(r, "Validation")
		if err != nil {
			u.Respond(w, u.Message(false, err.Error()))
			w.WriteHeader(http.StatusUnauthorized)
			logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена: ", err.Error())
			return
		}

		// Добавляем
		ctx := context.WithValue(r.Context(), TokenCtx, token)
		r = r.WithContext(ctx)

		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- токен успешно проверен ")
		// Вызываем следующий обработчик с обновленным запросом
		next.ServeHTTP(w, r)
	}
}

// JwtAuthentication проверяет JWT токен. Вытаскивает из заголовка токен, сверяет подпись, временную метку.
func JwtAuthentication(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := u.ExtractToken(r, "Authorization")
		if err != nil {
			http.Error(w, "Ошибка: "+err.Error(), http.StatusUnauthorized)
			logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при извлечении токена: ", err.Error())
			return
		}

		claims, err := validateToken(token)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- ошибка при проверке токена: ", err.Error())
			return
		}

		// Добавляем ID пользователя в контекст запроса
		ctx := context.WithValue(r.Context(), UserIDCtx, claims.UserId)
		r = r.WithContext(ctx)

		logger.Log.Error("--", r.URL.Path, " -- ", r.RemoteAddr, " -- токен успешно проверен ")
		// Вызываем следующий обработчик с обновленным запросом
		next.ServeHTTP(w, r)
	}
}

// validateToken проверяет токен и возвращает claims.
func validateToken(tokenString string) (*models.Token, error) {
	// Парсинг токена
	token, err := jwt.ParseWithClaims(tokenString, &models.Token{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("token_password")), nil
	})

	// Проверка на ошибки парсинга
	if err != nil {
		// Перевод типа
		ve, ok := err.(*jwt.ValidationError)
		// Если перевод удался, смотрим на ошибку
		if ok && ve.Errors == jwt.ValidationErrorExpired {
			return nil, fmt.Errorf("срок действия токена истек")
		}
		// Возврат если перевод не удался или другая ошибка
		return nil, fmt.Errorf("неверный токен аутентификации")
	}

	// Проверка валидности токена
	if !token.Valid {
		return nil, fmt.Errorf("токен недействителен")
	}

	// Извлечение claims
	claims, ok := token.Claims.(*models.Token)
	if !ok {
		return nil, fmt.Errorf("неверная структура токена")
	}

	// Шаг 5: Возврат успешного результата
	return claims, nil
}
