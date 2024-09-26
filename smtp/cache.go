package smtp

import (
	"app/models"
	"context"
	"sync"
	"time"
)

// Cache представляет кэш для хранения аккаунтов, ожидающих подтверждения или восстановления
type Cache struct {
	mu              sync.RWMutex
	accountLiveTime time.Duration
	clearInterval   time.Duration
	accounts        map[string]CachedAccount
}

// CachedAccount представляет аккаунт, ожидающий подтверждения или восстановления
type CachedAccount struct {
	Account      models.Account // Встраивание полей базовой структуры "аккаунт"
	Key          string         // Ключ, который отправляется на почту
	IsAuthorized bool           // Статус, указывающий, прошел ли данный токен валидацию через почту
	ExpiredAt    time.Time      // Время, когда аккаунт истечет
}

// NewCache создает новый экземпляр Cache
func NewCache(accountLiveTime, clearInterval time.Duration) *Cache {
	cache := &Cache{
		accounts:        make(map[string]CachedAccount),
		accountLiveTime: accountLiveTime,
		clearInterval:   clearInterval,
	}
	return cache
}

// StartClean запускает периодическую очистку просроченных элементов кэша
func (ca *Cache) StartClean(ctx context.Context) {
	ticker := time.NewTicker(ca.clearInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ca.cleanExpired()
		case <-ctx.Done():
			return
		}
	}
}

// cleanExpired удаляет все просроченные элементы из кэша
func (ca *Cache) cleanExpired() {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	now := time.Now()
	for key, value := range ca.accounts {
		if now.After(value.ExpiredAt) {
			delete(ca.accounts, key)
		}
	}
}

// Set устанавливает значение в кэше
func (ca *Cache) Set(key string, value CachedAccount) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	value.ExpiredAt = time.Now().Add(ca.accountLiveTime)
	ca.accounts[key] = value
}

// Get возвращает значение из кэша и признак его наличия
func (ca *Cache) Get(key string) (CachedAccount, bool) {
	ca.mu.RLock()
	value, ok := ca.accounts[key]
	ca.mu.RUnlock()

	if !ok || time.Now().After(value.ExpiredAt) {
		ca.DeleteExpired(key)
		return CachedAccount{}, false
	}

	return value, true
}

// DeleteExpired удаляет просроченное значение по ключу
func (ca *Cache) DeleteExpired(key string) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	value, ok := ca.accounts[key]
	if !ok {
		return false
	}

	if time.Now().After(value.ExpiredAt) {
		delete(ca.accounts, key)
		return true
	}

	return false
}

// Delete удаляет значение из кэша по ключу
func (ca *Cache) Delete(key string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	delete(ca.accounts, key)
}

// GetAccountStatus возвращает статус авторизации аккаунта
func (ca *Cache) GetAccountStatus(key string) bool {
	value, ok := ca.Get(key)
	return ok && value.IsAuthorized
}

// Update обновляет существующий аккаунт в кэше
func (ca *Cache) Update(key string, updateFunc func(*CachedAccount) bool) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	value, ok := ca.accounts[key]
	if !ok || time.Now().After(value.ExpiredAt) {
		delete(ca.accounts, key)
		return false
	}

	if updated := updateFunc(&value); updated {
		value.ExpiredAt = time.Now().Add(ca.accountLiveTime) // Обновляем время истечения
		ca.accounts[key] = value
		return true
	}

	return false
}

// Len возвращает количество элементов в кэше
func (ca *Cache) Len() int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.accounts)
}
