# JWT Authentication Service

Учебный проект сервиса аутентификации на Go с использованием JWT токенов. Создан для изучения основ работы с:
- JWT токенами
- REST API
- Базами данных
- Отправкой email

## Основные функции

- Регистрация пользователей с подтверждением по email
- Аутентификация через JWT токены
- Восстановление пароля
- Управление API ключами

## API Endpoints

### Регистрация
```http
POST /api/user/new
{
    "email": "user@example.com",
    "password": "password",
    "name": "User"
}
```

### Вход
```http
POST /api/user/login
{
    "email": "user@example.com",
    "password": "password"
}
```

## Используемые технологии

- Go
- JWT (github.com/dgrijalva/jwt-go)
- PostgreSQL
- SMTP для email

## Запуск проекта

1. Клонируйте репозиторий
```bash
git clone https://github.com/yourusername/jwt-auth-service.git
cd jwt-auth-service
```

2. Создайте файл .env на основе example.env и настройте его

3. Запустите:
```bash
go mod download
go run cmd/app/main.go
```

## Структура проекта

```
.
├── cmd/
│   └── app/main.go       # Запуск сервера
├── internal/             # Код проекта
│   ├── handler/          # Обработчики запросов
│   ├── models/           # Модели данных
│   ├── smtp/             # Отправка почты
│   └── utils/            # Вспомогательные функции
└── README.md
```