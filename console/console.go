package console

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

const baseURL = "http://localhost:8000"

type ServerResponse struct {
	Account interface{} `json:"account"`
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Token   string      `json:"token,omitempty"`
}

type Account struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"`
	APIKey    string `json:"api_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Token     string `json:"token,omitempty"`
}

type BaseHttpRequest struct {
	Account Account `json:"account"`
	Key     string  `json:"key"`
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
	if currentSession.Token != "" {
		fmt.Println("Сперва выйдите из аккаунта")
		return
	}

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
		if token, ok := resp.Account.(string); ok {
			currentSession.Token = token
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
	if currentSession.Token == "" {
		fmt.Println("Сначала зарегистрируйтесь или войдите в аккаунт")
		return
	}

	fmt.Print("Введите код подтверждения: ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Token: currentSession.Token,
		},
		Key: code,
	}

	resp, err := sendRequest("POST", "/api/user/new/validate", baseHttpRequest)
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
	if currentSession.Token != "" {
		fmt.Println("Сперва выйдите из аккаунта")
		return
	}

	fmt.Print("Введите email: ")
	email, _ := reader.ReadString('\n')
	email = strings.TrimSpace(email)

	fmt.Print("Введите пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	requestData := struct {
		Account struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"account"`
	}{
		Account: struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{
			Email:    email,
			Password: password,
		},
	}

	resp, err := sendRequest("POST", "/api/user/login", requestData)
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
		fmt.Println("Код для сброса пароля отправлен на почту")
		validatePasswordReset(reader, email)
	} else {
		fmt.Println("Ошибка при запросе сброса пароля:", resp.Message)
	}
}

func validatePasswordReset(reader *bufio.Reader, email string) {
	fmt.Print("Введите код подтверждения: ")
	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Email: email,
		},
		Key: code,
	}

	resp, err := sendRequest("POST", "/api/user/password/validate", baseHttpRequest)
	if err != nil {
		fmt.Println("Ошибка при подтверждении кода:", err)
		return
	}

	if resp.Status {
		fmt.Println("Код подтвержден. Установите новый пароль.")
		setNewPassword(reader, email, code)
	} else {
		fmt.Println("Ошибка при подтверждении кода:", resp.Message)
	}
}

func setNewPassword(reader *bufio.Reader, email, code string) {
	fmt.Print("Введите новый пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	baseHttpRequest := BaseHttpRequest{
		Account: Account{
			Email:    email,
			Password: password,
		},
		Key: code,
	}

	resp, err := sendRequest("POST", "/api/user/password/set", baseHttpRequest)
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
	if currentSession.Token == "" {
		fmt.Println("Сперва войдите в аккаунт")
		return
	}

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
			Token:     currentSession.Token,
		},
	}

	resp, err := sendRequest("POST", "/api/user/set-tokens", baseHttpRequest)
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
	if currentSession.Token == "" {
		fmt.Println("Сперва войдите в аккаунт")
		return
	}

	resp, err := sendRequest("POST", "/api/user/refresh", nil)
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
	if currentSession.Token == "" {
		fmt.Println("Вы не вошли в аккаунт")
		return
	}

	currentSession = Account{}
	fmt.Println("Выход из аккаунта выполнен успешно")
}

func sendRequest(method, path string, data interface{}) (ServerResponse, error) {
	var resp ServerResponse

	jsonData, err := json.Marshal(data)
	if err != nil {
		return resp, fmt.Errorf("ошибка при создании JSON: %v", err)
	}

	fmt.Printf("Отправляемые данные (JSON): %s\n", string(jsonData))

	req, err := http.NewRequest(method, baseURL+path, bytes.NewBuffer(jsonData))
	if err != nil {
		return resp, fmt.Errorf("ошибка при создании запроса: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if currentSession.Token != "" {
		req.Header.Set("Authorization", "Bearer "+currentSession.Token)
	}

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

	fmt.Printf("Ответ сервера (сырые данные): %s\n", string(body))

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return resp, fmt.Errorf("ошибка при разборе ответа: %v", err)
	}

	return resp, nil
}
