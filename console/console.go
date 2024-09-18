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
	Account Account `json:"account"`
	Status  bool    `json:"status"`
	Message string  `json:"message"`
	Token   string  `json:"token,omitempty"`
}

type Account struct {
	ID        uint   `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"`
	APIKey    string `json:"api_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Token     string `json:"token,omitempty"`
}

var currentSession Account

func StartUserInterface() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\nВыберите действие:")
		fmt.Println("1. Регистрация нового аккаунта")
		fmt.Println("2. Вход в аккаунт")
		fmt.Println("3. Установить токены")
		fmt.Println("4. Обновить JWT токен")
		fmt.Println("5. Выход из аккаунта")
		fmt.Println("6. Выход из программы")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			registerAccount(reader)
		case "2":
			loginAccount(reader)
		case "3":
			setTokens(reader)
		case "4":
			refreshToken()
		case "5":
			logOut()
		case "6":
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

	resp, err := sendRequest("POST", "/api/user/new", account)
	if err != nil {
		fmt.Println("Ошибка при регистрации:", err)
		return
	}

	if resp.Status {
		currentSession = resp.Account
		fmt.Println("Аккаунт успешно создан и выполнен вход")
	} else {
		fmt.Println("Ошибка при создании аккаунта:", resp.Message)
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

	account := Account{
		Email:    email,
		Password: password,
	}

	resp, err := sendRequest("POST", "/api/user/login", account)
	if err != nil {
		fmt.Println("Ошибка при входе:", err)
		return
	}

	if resp.Status {
		currentSession = resp.Account
		fmt.Println("Вход выполнен успешно")
	} else {
		fmt.Println("Ошибка при входе:", resp.Message)
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

	requestData := struct {
		APIKey    string `json:"api_key"`
		SecretKey string `json:"secret_key"`
	}{
		APIKey:    apiKey,
		SecretKey: secretKey,
	}

	fmt.Printf("Отправляемые данные: %+v\n", requestData)

	resp, err := sendRequest("POST", "/api/user/set-tokens", requestData)
	if err != nil {
		fmt.Println("Ошибка при установке токенов:", err)
		return
	}

	if resp.Status {
		fmt.Println("Токены успешно установлены")
	} else {
		fmt.Println("Ошибка при установке токенов:", resp.Message)
		fmt.Printf("Полный ответ сервера: %+v\n", resp)
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
		currentSession.Token = resp.Token
		fmt.Println("Токен успешно обновлен")
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

	fmt.Printf("Отправляемые данные (JSON): %s\n", string(jsonData)) // Добавим логирование JSON

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

	fmt.Printf("Ответ сервера (сырые данные): %s\n", string(body)) // Добавим логирование ответа

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return resp, fmt.Errorf("ошибка при разборе ответа: %v", err)
	}

	return resp, nil
}
