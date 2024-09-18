package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

func main() {
	// Конфигурация SMTP
	smtpMail := "awesome.gail@yandex.ru"
	smtpPassword := "nnczofiwvuivooil"
	smtpHost := "smtp.yandex.ru"
	smtpPort := 465

	// Настройка сообщения
	to := []string{"hackermanmitch@gmail.com"}
	subject := "Пивет!"
	body := "Это тестовое сообщение, отправленное с помощью Go.\n Привет, сегодня скину код с авторизацией через почту.\nМожет успею восстановление пароля сделать."

	message := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", smtpMail, to[0], subject, body)

	// Настройка аутентификации
	auth := smtp.PlainAuth("", smtpMail, smtpPassword, smtpHost)

	// Настройка TLS конфигурации
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         smtpHost,
	}

	// Установка соединения
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", smtpHost, smtpPort), tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Создание клиента
	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		log.Fatal(err)
	}

	// Аутентификация
	if err = client.Auth(auth); err != nil {
		log.Fatal(err)
	}

	// Настройка отправителя и получателя
	if err = client.Mail(smtpMail); err != nil {
		log.Fatal(err)
	}
	if err = client.Rcpt(to[0]); err != nil {
		log.Fatal(err)
	}

	// Отправка сообщения
	w, err := client.Data()
	if err != nil {
		log.Fatal(err)
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		log.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Закрытие соединения
	client.Quit()

	fmt.Println("Сообщение успешно отправлено!")
}
