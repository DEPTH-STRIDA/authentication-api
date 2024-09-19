// Пакет предоставляет возможности регистрации/востановления аккаунта.
package smtp

import (
	"app/models"
	"app/request"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/patrickmn/go-cache"
)

// Глобальная переменная для взаимодействия с другими пакетами
var MailManager *SmtpManager

// Менеджер почты
type SmtpManager struct {
	smtpMail, smtpPassword, smtpHost string
	smtpPort                         int
	mu                               sync.Mutex
	client                           *smtp.Client

	requester *request.RequestHandler
	cache     *cache.Cache
}

// Аккаунт ожидающий подтверждения или восстановления
type AwaitingAccount struct {
	Account *models.Account

	Key          string
	isAuthorized bool
	sendTime     time.Time
}

// init запускается автоматически и иницилизирует smtp менеджео
func init() {
	// Загрузка файла .env
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file:", err)
	}

	// Чтение переменных окружения
	smtpMail := os.Getenv("smtp_mail")
	smtpPassword := os.Getenv("smtp_password")
	smtpHost := os.Getenv("smtp_host")
	smtpPort, err := strconv.Atoi(os.Getenv("smtp_port"))
	if err != nil {
		fmt.Println("Error parsing SMTP port:", err)
		smtpPort = 465 // default port
	}

	// "Откладыватель"
	requester, err := request.NewRequestHandler(100)
	if err != nil {
		fmt.Println("Error creating request handler:", err)
	}

	// Выполнение отложенных функций раз в 15 секунд без увеличения времени при burst
	go requester.ProcessRequests(15 * time.Second)

	MailManager = &SmtpManager{
		smtpMail:     smtpMail,
		smtpPassword: smtpPassword,
		smtpHost:     smtpHost,
		smtpPort:     smtpPort,
		requester:    requester,
		cache:        cache.New(15*time.Minute, 30*time.Minute),
	}
}

// AuthorizeEmail зарегистрирует пользователя в кеша, отправит ему сообщение с кодом.
// Возвращает код, который должен прислать пользователь
func (sm *SmtpManager) ValidateEmail(account *models.Account) error {
	rand.Seed(time.Now().UnixNano())
	code := rand.Intn(100000)
	key := fmt.Sprintf("%05d", code)

	awaitingAccount := AwaitingAccount{
		Account:      account,
		Key:          key,
		isAuthorized: false,
		sendTime:     time.Now(),
	}

	// Отправляем отложенный запрос на регистрацию.
	sm.requester.HandleRequest(func() error {
		sm.sendConfirmationEmail(awaitingAccount)
		return nil
	})

	// Добавляем в кеш данные
	sm.cache.Set(awaitingAccount.Account.Token, awaitingAccount, 15*time.Minute)

	return nil
}

// DeleteUser удаляет пользователя из бд
func (sm *SmtpManager) DeleteUser(token string) {
	sm.cache.Delete(token)
}

func (sm *SmtpManager) CheckKey(account *models.Account, key string) (*models.Account, error) {
	// Запрос из кеша
	accountCached, ok := sm.cache.Get(account.Token)
	if !ok {
		return nil, fmt.Errorf("данный пользователь не ожидает подтверждения: ")
	}
	// Перевод типа
	awaitingAccount, ok := accountCached.(AwaitingAccount)
	if !ok {
		fmt.Println("Ошибка при перевода типа AwaitingAccount")
		return nil, fmt.Errorf("данный пользователь не ожидает подтверждения: ")
	}

	// Сравнение ключей
	isPass := awaitingAccount.Key == key

	// Возврат, если ключ не тот
	if !isPass {
		return nil, fmt.Errorf("неправильный ключ")
	}

	// Установка статуса (авторизация пройдена)
	awaitingAccount.isAuthorized = true
	// Обновление данных в кеше
	sm.cache.Set(account.Token, awaitingAccount, 15*time.Second)

	return awaitingAccount.Account, nil
}

func (sm *SmtpManager) CheckAuthorized(token string) (*models.Account, bool) {
	// Запрос из кеша
	accountCached, ok := sm.cache.Get(token)
	if !ok {
		return nil, false
	}
	// Перевод типа
	awaitingAccount, ok := accountCached.(AwaitingAccount)
	if !ok {
		fmt.Println("Ошибка при перевода типа AwaitingAccount")
		return nil, false
	}

	return awaitingAccount.Account, awaitingAccount.isAuthorized
}

func (sm *SmtpManager) IsConsist(Email string) bool {
	for _, v := range MailManager.cache.Items() {
		// fmt.Printf("Ключ: %s, Значение: %v\n", k, v.Object)
		accountTyped, ok := v.Object.(AwaitingAccount)
		if !ok {
			continue
		}
		if accountTyped.Account.Email == Email {
			return true
		}
	}
	return false
}

func (sm *SmtpManager) sendConfirmationEmail(awaitingAccount AwaitingAccount) error {
	subject := "Подтверждение регистрации на сайте biance service"
	body := fmt.Sprintf("Ваш код подтверждения: %s", awaitingAccount.Key)

	return sm.sendEmailMessage([]string{awaitingAccount.Account.Email}, subject, body)
}

func (sm *SmtpManager) sendPasswordReset(awaitingAccount AwaitingAccount) error {
	subject := "Сброс пароля на сайте biance service"
	body := fmt.Sprintf("Ваш код подтверждения: %s", awaitingAccount.Key)

	return sm.sendEmailMessage([]string{awaitingAccount.Account.Email}, subject, body)
}

func (sm *SmtpManager) connect() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.client != nil {
		return nil
	}

	// Настройка TLS конфигурации
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sm.smtpHost,
	}

	// Установка соединения
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", sm.smtpHost, sm.smtpPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("error establishing connection: %v", err)
	}

	// Создание клиента
	client, err := smtp.NewClient(conn, sm.smtpHost)
	if err != nil {
		conn.Close()
		return fmt.Errorf("error creating SMTP client: %v", err)
	}

	// Аутентификация
	auth := smtp.PlainAuth("", sm.smtpMail, sm.smtpPassword, sm.smtpHost)
	if err = client.Auth(auth); err != nil {
		client.Close()
		return fmt.Errorf("authentication error: %v", err)
	}

	sm.client = client
	return nil
}

func (sm *SmtpManager) Close() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.client != nil {
		err := sm.client.Quit()
		sm.client = nil
		return err
	}
	return nil
}

func (sm *SmtpManager) sendEmailMessage(to []string, subject, body string) error {
	if err := sm.connect(); err != nil {
		return err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Формирование сообщения
	message := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", sm.smtpMail, to[0], subject, body)

	// Настройка отправителя и получателя
	if err := sm.client.Mail(sm.smtpMail); err != nil {
		return fmt.Errorf("error specifying sender: %v", err)
	}
	for _, recipient := range to {
		if err := sm.client.Rcpt(recipient); err != nil {
			return fmt.Errorf("error specifying recipient %s: %v", recipient, err)
		}
	}

	// Отправка сообщения
	w, err := sm.client.Data()
	if err != nil {
		return fmt.Errorf("error preparing data: %v", err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("error writing message: %v", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("error closing writer: %v", err)
	}

	return nil
}
