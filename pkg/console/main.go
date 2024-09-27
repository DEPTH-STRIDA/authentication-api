package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	StartUserInterface()
}

const baseURL = "http://localhost:8000"

type ServerResponse struct {
	Account interface{} `json:"account"`
	Status  bool        `json:"status"`
	Message string      `json:"message"`
}

type Account struct {
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"`
	APIKey    string `json:"api_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Token     string `json:"token,omitempty"`
}

type BaseHttpRequest struct {
	Account Account `json:"account"`
	Key     string  `json:"key,omitempty"`
}

var currentSession Account

func StartUserInterface() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\nВыберите действие:")
		fmt.Println("1. Регистрация нового аккаунта")
		fmt.Println("2. Подтверждение почты")
		fmt.Println("3. Вход в аккаунт")
		fmt.Println("4. Восстановление пароля")
		fmt.Println("5. Установить токены")
		fmt.Println("6. Обновить JWT токен")
		fmt.Println("7. Выход из аккаунта")
		fmt.Println("8. Выход из программы")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			registerAccount(reader)
		case "2":
			confirmEmail(reader)
		case "3":
			loginAccount(reader)
		case "4":
			resetPassword(reader)
		case "5":
			setTokens(reader)
		case "6":
			refreshToken()
		case "7":
			logOut()
		case "8":
			fmt.Println("До свидания!")
			return
		default:
			fmt.Println("Неверный выбор. Попробуйте снова.")
		}
	}
}

func registerAccount(reader *bufio.Reader) {
	fmt.Print("Введите email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Введите пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	account := Account{
		Email:    email,
		Password: password,
	}

	baseHttpRequest := BaseHttpRequest{
		Account: account,
	}

	resp, err := sendRequest("POST", "/api/user/new", baseHttpRequest)
	if err != nil {
		fmt.Println("Ошибка при регистрации:", err)
		return
	}

	if resp.Status {
		if accountData, ok := resp.Account.(map[string]interface{}); ok {
			currentSession.Token = accountData["token"].(string)
			currentSession.Email = email
			fmt.Println("Аккаунт успешно создан. Проверьте почту для подтверждения.")
		} else {
			fmt.Println("Ошибка: неожиданный формат ответа от сервера")
		}
	} else {
		fmt.Println("Ошибка при создании аккаунта:", resp.Message)
	}
}

func confirmEmail(reader *bufio.Reader) {
	fmt.Print("Введите код подтверждения: ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Token: currentSession.Token,
		},
		Key: code,
	}

	resp, err := sendRequestWithHeader("POST", "/api/user/new/validate", baseHttpRequest, "Authorization", currentSession.Token)
	if err != nil {
		fmt.Println("Ошибка при подтверждении почты:", err)
		return
	}

	if resp.Status {
		fmt.Println("Почта успешно подтверждена")
	} else {
		fmt.Println("Ошибка при подтверждении почты:", resp.Message)
	}
}

func loginAccount(reader *bufio.Reader) {
	fmt.Print("Введите email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Введите пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	account := Account{
		Email:    email,
		Password: password,
	}

	baseHttpRequest := BaseHttpRequest{
		Account: account,
	}

	resp, err := sendRequest("POST", "/api/user/login", baseHttpRequest)
	if err != nil {
		fmt.Println("Ошибка при входе:", err)
		return
	}

	if resp.Status {
		if accountData, ok := resp.Account.(map[string]interface{}); ok {
			currentSession.Token = accountData["token"].(string)
			currentSession.Email = email
			fmt.Println("Вход выполнен успешно")
		} else {
			fmt.Println("Ошибка: неожиданный формат ответа от сервера")
		}
	} else {
		fmt.Println("Ошибка при входе:", resp.Message)
	}
}

func resetPassword(reader *bufio.Reader) {
	fmt.Print("Введите email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Email: email,
		},
	}

	resp, err := sendRequest("POST", "/api/user/password/reset", baseHttpRequest)
	if err != nil {
		fmt.Println("Ошибка при запросе сброса пароля:", err)
		return
	}

	if resp.Status {
		if accountData, ok := resp.Account.(map[string]interface{}); ok {
			token := accountData["token"].(string)
			fmt.Println("Код для сброса пароля отправлен на почту")
			validatePasswordReset(reader, token)
		} else {
			fmt.Println("Ошибка: неожиданный формат ответа от сервера")
		}
	} else {
		fmt.Println("Ошибка при запросе сброса пароля:", resp.Message)
	}
}

func validatePasswordReset(reader *bufio.Reader, token string) {
	fmt.Print("Введите код подтверждения: ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Email: currentSession.Email,
		},
		Key: code,
	}

	resp, err := sendRequestWithHeader("POST", "/api/user/password/validate", baseHttpRequest, "Authorization", token)
	if err != nil {
		fmt.Println("Ошибка при подтверждении кода:", err)
		return
	}

	if resp.Status {
		if accountData, ok := resp.Account.(map[string]interface{}); ok {
			newToken := accountData["token"].(string)
			fmt.Println("Код подтвержден. Установите новый пароль.")
			setNewPassword(reader, newToken)
		} else {
			fmt.Println("Ошибка: неожиданный формат ответа от сервера")
		}
	} else {
		fmt.Println("Ошибка при подтверждении кода:", resp.Message)
	}
}

func setNewPassword(reader *bufio.Reader, token string) {
	fmt.Print("Введите новый пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Email:    currentSession.Email,
			Password: password,
		},
	}

	resp, err := sendRequestWithHeader("POST", "/api/user/password/set", baseHttpRequest, "Authorization", token)
	if err != nil {
		fmt.Println("Ошибка при установке нового пароля:", err)
		return
	}

	if resp.Status {
		fmt.Println("Новый пароль успешно установлен")
	} else {
		fmt.Println("Ошибка при установке нового пароля:", resp.Message)
	}
}

func setTokens(reader *bufio.Reader) {
	fmt.Print("Введите публичный токен: ")
	apiKey, _ := reader.ReadString('\n')
	apiKey = strings.TrimSpace(apiKey)

	fmt.Print("Введите приватный токен: ")
	secretKey, _ := reader.ReadString('\n')
	secretKey = strings.TrimSpace(secretKey)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			APIKey:    apiKey,
			SecretKey: secretKey,
		},
	}

	resp, err := sendRequestWithHeader("POST", "/api/user/set-tokens", baseHttpRequest, "Authorization", currentSession.Token)
	if err != nil {
		fmt.Println("Ошибка при установке токенов:", err)
		return
	}

	if resp.Status {
		fmt.Println("Токены успешно установлены")
	} else {
		fmt.Println("Ошибка при установке токенов:", resp.Message)
	}
}

func refreshToken() {
	resp, err := sendRequestWithHeader("POST", "/api/user/refresh", nil, "Authorization", currentSession.Token)
	if err != nil {
		fmt.Println("Ошибка при обновлении токена:", err)
		return
	}

	if resp.Status {
		if accountData, ok := resp.Account.(map[string]interface{}); ok {
			currentSession.Token = accountData["token"].(string)
			fmt.Println("Токен успешно обновлен")
		} else {
			fmt.Println("Ошибка: неожиданный формат ответа от сервера")
		}
	} else {
		fmt.Println("Ошибка при обновлении токена:", resp.Message)
	}
}

func logOut() {
	currentSession = Account{}
	fmt.Println("Выход из аккаунта выполнен успешно")
}

func sendRequest(method, path string, data interface{}) (ServerResponse, error) {
	return sendRequestWithHeader(method, path, data, "", "")
}

func sendRequestWithHeader(method, path string, data interface{}, headerKey, headerValue string) (ServerResponse, error) {
	var resp ServerResponse

	jsonData, err := json.Marshal(data)
	if err != nil {
		return resp, fmt.Errorf("ошибка при создании JSON: %v", err)
	}

	req, err := http.NewRequest(method, baseURL+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return resp, fmt.Errorf("ошибка при создании запроса: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if headerKey != "" && headerValue != "" {
		req.Header.Set(headerKey, "Bearer "+headerValue)
	}

	// Логирование запроса
	fmt.Printf("Отправляется запрос:\nМетод: %s\nURL: %s\nЗаголовки: %v\nТело: %s\n\n",
		req.Method, req.URL, req.Header, string(jsonData))

	client := &http.Client{}
	httpResp, err := client.Do(req)
	if err != nil {
		return resp, fmt.Errorf("ошибка при отправке запроса: %v", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return resp, fmt.Errorf("ошибка при чтении ответа: %v", err)
	}

	// Логирование ответа
	fmt.Printf("Получен ответ:\nСтатус: %s\nТело: %s\n\n",
		httpResp.Status, string(body))

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return resp, fmt.Errorf("ошибка при разборе ответа: %v", err)
	}

	return resp, nil
}
