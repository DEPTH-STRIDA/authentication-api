package middleware

import (
	"app/models"
	u "app/utils"
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type NotAuthRoutes struct {
	Routes []string
}

var NotAuth NotAuthRoutes

func JwtAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Starting JwtAuthentication middleware")

		requestPath := r.URL.Path
		log.Printf("Request path: %s", requestPath)

		for _, value := range NotAuth.Routes {
			if value == requestPath {
				log.Printf("Skipping authentication for path: %s", requestPath)
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenHeader := r.Header.Get("Authorization")
		log.Printf("Received token: %s", tokenHeader)

		if tokenHeader == "" {
			log.Println("Error: Missing authentication token")
			response := u.Message(false, "Отсутствует токен аутентификации")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		splitted := strings.Split(tokenHeader, " ")
		if len(splitted) != 2 {
			log.Println("Error: Invalid token format")
			response := u.Message(false, "Неверный формат токена аутентификации")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		tokenPart := splitted[1]
		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil {
			log.Printf("Error parsing token: %v", err)
			if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorExpired != 0 {
					log.Println("Error: Token has expired")
					response := u.Message(false, "Срок действия токена истек")
					w.WriteHeader(http.StatusUnauthorized)
					w.Header().Add("Content-Type", "application/json")
					u.Respond(w, response)
					return
				}
			}

			log.Println("Error: Invalid authentication token")
			response := u.Message(false, "Неверный токен аутентификации")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		if !token.Valid {
			log.Println("Error: Token is not valid")
			response := u.Message(false, "Токен недействителен")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		timeUntilExpiration := time.Until(time.Unix(tk.ExpiresAt, 0))
		log.Printf("Time until token expiration: %v", timeUntilExpiration)
		if timeUntilExpiration < 5*time.Minute {
			log.Println("Token is about to expire, adding X-Refresh-Token header")
			w.Header().Add("X-Refresh-Token", "true")
		}

		log.Printf("Authenticated user ID: %d", tk.UserId)

		ctx := context.WithValue(r.Context(), "user", tk.UserId)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
