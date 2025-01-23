// handlers хранит http обработчики.
package handler

import (
	u "app/internal/utils"
	"net/http"
)

// NotFoundHandler обрабатывает случае, когда для пути не найден обработчик
func NotFoundHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Установка HHTP-ответа статуса StatusNotFound
		w.WriteHeader(http.StatusNotFound)
		// Установка ответа в тело
		u.Respond(w, u.Message(false, "This resources was not found on our server"))
		// Передача обработчика дальше
		next.ServeHTTP(w, r)
	})
}
