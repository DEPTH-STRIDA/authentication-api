package smtp

import (
	"app/models"
	"sync"
	"time"
)

// Кеш для хранения аккаунтов, которые нахождятся на проверка перед создание аккаунта
type Cache struct {
	mu sync.RWMutex

	accountLiveTime time.Duration
	clearInterval   time.Duration

	accounts map[string]CachedAccount
}

// Аккаунт ожидающий подтверждения или восстановления
type CachedAccount struct {
	Account models.Account // Встривание полей базовой структуры "аккаунт"

	Key          string    // ключ, который отправлется на почту
	isAuthorized bool      // Статус, который указываеть прошел ли данный токен валидацию через почту и может ли создавать аккаунт или менять пароль
	expiredAt    time.Time // Время, когда аккаунт истечет
}

// NewCacheAccount конструктор CacheAccount
func NewCacheAccount(accountLiveTime time.Duration, clearInterval time.Duration) *Cache {

	cache := &Cache{
		accounts:        make(map[string]CachedAccount),
		accountLiveTime: accountLiveTime,
		clearInterval:   clearInterval,
	}
	go cache.startClean()

	return cache
}

// startClean запускает горутину, которая раз в интервал времени запускает очистку кеша
func (ca *Cache) startClean() {
	ticker := time.NewTicker(ca.clearInterval)

	for {
		select {
		case <-ticker.C:
			ca.clean()
		}
	}
}

// cleanC проходится по кешу и удаляем данные с истекшим сроком
func (ca *Cache) clean() {
	for i, _ := range ca.accounts {
		ca.Delete(i)
	}
}

// Set устанавливает значение в мапе
func (ca *Cache) Set(key string, value CachedAccount) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	value.expiredAt = time.Now().Add(ca.accountLiveTime)

	ca.accounts[key] = value
}

// Get возвращает значение из мапы и наличие в мапе
func (ca *Cache) Get(key string) (CachedAccount, bool) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	value, ok := ca.accounts[key]
	// Если структура просрочена, то удаляем
	if time.Now().After(value.expiredAt) {
		go ca.Delete(key)
		return CachedAccount{}, false
	}

	return value, ok
}

// Delete удаляет значению по ключу
func (ca *Cache) Delete(key string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	delete(ca.accounts, key)
}

// GetAccountStatus возвращает статус аккаунта, либо отстутствие в кеше
func (ca *Cache) GetAccountStatus(key string) bool {
	ca.mu.RLock()
	ca.mu.RUnlock()

	value, ok := ca.accounts[key]
	if !ok {
		return false
	}
	// Если структура просрочена, то удаляем
	if time.Now().After(value.expiredAt) {
		go ca.Delete(key)
		return false
	}

	return value.isAuthorized
}
