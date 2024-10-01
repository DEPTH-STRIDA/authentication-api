package handler

import "app/models"

// Базовый запрос. Универсален для всех обработчиков.
type BaseHttpRequest struct {
	Account models.Account `json:"account"`
	Key     string         `json:"key"`
}
