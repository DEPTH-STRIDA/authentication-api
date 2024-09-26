// Пакет предоставляет возможности регистрации/востановления аккаунта.
package smtp

import (
	"app/models"
	"app/request"
	u "app/utils"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/smtp"
	"os"
	"strconv"
	"sync"
	"time"
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
	cache     *Cache
}

// NewSmtpManager получает файлы из окружения, создает откладыватель, запускает откладыватель, возвращает структуру SmtpManager
func NewSmtpManager() (*SmtpManager, error) {
	// Чтение переменных окружения
	smtpMail := os.Getenv("smtp_mail")
	if smtpMail == "" {
		return nil, fmt.Errorf("smtp_mail is empty")
	}

	smtpPassword := os.Getenv("smtp_password")
	if smtpPassword == "" {
		return nil, fmt.Errorf("smtp_password is empty")
	}

	smtpHost := os.Getenv("smtp_host")
	if smtpHost == "" {
		return nil, fmt.Errorf("smtp_host is empty")
	}

	smtpPort, err := strconv.Atoi(os.Getenv("smtp_port"))
	if err != nil {
		return nil, fmt.Errorf("error parsing SMTP port: %e", err)
	}

	// "Откладыватель"
	requester, err := request.NewRequestHandler(100)
	if err != nil {
		return nil, fmt.Errorf("error creating request handler: %e", err)
	}

	// Выполнение отложенных функций раз в 15 секунд без увеличения времени при burst
	go requester.ProcessRequests(15 * time.Second)

	MailManager = &SmtpManager{
		smtpMail:     smtpMail,
		smtpPassword: smtpPassword,
		smtpHost:     smtpHost,
		smtpPort:     smtpPort,
		requester:    requester,
		cache:        NewCache(15*time.Minute, 15*time.Minute),
	}

	return MailManager, nil
}

// ValidateEmail отправляет код на почту, заносит в кеш данные аккаунта. Возвращает токен.
func (sm *SmtpManager) ValidateEmail(account models.Account) (string, error) {
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	code := r.Intn(100000)
	key := fmt.Sprintf("%05d", code)

	awaitingAccount := CachedAccount{
		Account:      account,
		Key:          key,
		IsAuthorized: false,
	}

	// Отправляем отложенный запрос на регистрацию.
	sm.requester.HandleRequest(func() error {
		sm.sendConfirmationEmail(awaitingAccount)
		return nil
	})

	// Добавляем в кеш данные
	token := u.GenerateSecureToken(32)
	sm.cache.Set(token, awaitingAccount)

	return token, nil
}

// CheckKey проверяет ключ в почте, устанавливает статус. Возвращает новый токен.
func (sm *SmtpManager) CheckKey(token, key string) (string, error) {
	// Запрос из кеша
	accountCached, ok := sm.cache.Get(token)
	if !ok {
		return "", fmt.Errorf("данный пользователь не ожидает подтверждения: ")
	}

	// Возврат, если ключ не тот
	if !(accountCached.Key == key) {
		return "", fmt.Errorf("неправильный ключ")
	}

	// Установка статуса (авторизация пройдена)
	accountCached.IsAuthorized = true
	sm.cache.Delete(token)

	newToken := u.GenerateSecureToken(32)
	sm.cache.Set(newToken, accountCached)
	// Обновление данных в кеше
	sm.cache.Set(token, accountCached)

	return newToken, nil
}

// CheckStatus проверяет статус аккаунта. Возвращает bool.
func (sm *SmtpManager) CheckStatus(token string) (models.Account, bool) {
	// Запрос из кеша
	accountCached, ok := sm.cache.Get(token)
	if !ok {
		return models.Account{}, false
	}

	// Возврат, если ключ не тот
	if accountCached.IsAuthorized {
		return accountCached.Account, true
	}

	return models.Account{}, false
}

// Delete удаляет аккаунт из кеша.
func (sm *SmtpManager) Delete(token string) {
	sm.cache.Delete(token)
}

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

func (sm *SmtpManager) sendConfirmationEmail(awaitingAccount CachedAccount) error {
	fmt.Println("Отправка сообщения подтверждения на почту: ", awaitingAccount.Account.Email)
	subject := "Подтверждение регистрации на сайте biance service"
	body := fmt.Sprintf("Ваш код подтверждения: %s", awaitingAccount.Key)

	return sm.sendEmailMessage([]string{awaitingAccount.Account.Email}, subject, body)
}

func (sm *SmtpManager) sendPasswordReset(awaitingAccount CachedAccount) error {
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
