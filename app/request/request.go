// request предназначен для предоставления возможности откладывать выполнение функций.
// Функции (запросы) обрабатываются fifo.
package request

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Request запроса, который кладется в "откладыватель"
type Request func() error

// Откладыватель
type RequestHandler struct {
	requests            chan Request // Канал с запросами базовой важности
	lowPriorityRequests chan Request // Канал с запросами пониженной важности. Пока не будут выполненый все запросы базовой важности, обработка пониженной не запустится.
	ctx                 context.Context
	cancel              context.CancelFunc
	mu                  sync.Mutex
	isProcessing        bool
}

// NewRequestHandler конструктор "откладывателя"
func NewRequestHandler(bufferSize int64) (*RequestHandler, error) {
	ctx, cancel := context.WithCancel(context.Background())
	requestApp := RequestHandler{
		requests:            make(chan Request, bufferSize),
		lowPriorityRequests: make(chan Request, bufferSize),
		ctx:                 ctx,
		cancel:              cancel,
	}

	return &requestApp, nil
}

// HandleRequest добавляет запрос в очередь
func (app *RequestHandler) HandleRequest(req Request) error {
	app.mu.Lock()
	if !app.isProcessing {
		return errors.New("не удаться добавить запрос в обработчик-откладыватель. Обработка не запущена")
	}
	app.mu.Unlock()

	app.requests <- req
	return nil
}

// HandlePriorityRequest добавляет низко-приоритетный запрос в очередь
func (app *RequestHandler) HandleLowPriorityRequest(req Request) error {
	app.mu.Lock()
	if !app.isProcessing {
		return errors.New("не удаться добавить запрос в обработчик-откладыватель. Обработка не запущена")
	}
	app.mu.Unlock()

	app.lowPriorityRequests <- req
	return nil
}

// ProcessRequests запускает обработку из канала. Между выполнением функций будет выполнена обязательная пауза pause
// Для добавление запросов в очередь, передайте запрос в HandleRequest или HandleLowPriorityRequest
func (app *RequestHandler) ProcessRequests(pause time.Duration) {
	app.mu.Lock()
	if app.isProcessing {
		app.mu.Unlock()
		return
	}
	app.isProcessing = true
	app.mu.Unlock()
	for {
		select {
		case <-app.ctx.Done():
			app.isProcessing = false
			return
		case req := <-app.requests:
			err := req()
			if err != nil {
				fmt.Println("Ошибка при выполнении запроса: ", err)
			}
		case req := <-app.lowPriorityRequests:
			err := req()
			if err != nil {
				fmt.Println("Ошибка при выполнении приоритетного запроса: ", err)
			}
		}
		time.Sleep(pause)
	}
}

// ProcessRequests запускает обработку из канала. Если между концом выполнения запросы и начало нового не успеет пройти minPause времение,
// то пауза будет увеличина по правилу HandleLowPriorityRequest. defaultPause - стандартная пауза, после конца запроса.
// Для добавление запросов в очередь, передайте запрос в HandleRequest или HandleLowPriorityRequest
func (app *RequestHandler) ProcessRequestsWithDynamicPause(defaultPause time.Duration, incrementPause func(currentPause time.Duration) time.Duration) {
	app.mu.Lock()
	if app.isProcessing {
		fmt.Println("Невозможно запустить обработку запросов ProcessRequestsWithDynamicPause. Обработка уже запущена.")
		app.mu.Unlock()
		return
	}
	app.isProcessing = true
	app.mu.Unlock()

	currentPause := defaultPause
	consecutiveRequests := 0

	for {
		select {
		case <-app.ctx.Done():
			app.isProcessing = false
			return
		case req := <-app.requests:
			consecutiveRequests++
			err := req()
			if err != nil {
				fmt.Println("Ошибка при выполнении запроса: ", err)
			}
		case req := <-app.lowPriorityRequests:
			consecutiveRequests++
			err := req()
			if err != nil {
				fmt.Println("Ошибка при выполнении приоритетного запроса: ", err)
			}
		default:
			// Если нет запросов, сбрасываем счетчик и паузу
			consecutiveRequests = 0
			currentPause = defaultPause
			time.Sleep(defaultPause)
			continue
		}

		// Увеличиваем паузу, если обработано несколько запросов подряд
		if consecutiveRequests > 1 {
			currentPause = incrementPause(currentPause)
		} else {
			currentPause = defaultPause
		}

		time.Sleep(currentPause)
	}
}

// StopProcessing останавливает обработку запросов
func (app *RequestHandler) StopProcessing() {
	app.cancel() // Отменяем контекст
	app.mu.Lock()
	app.isProcessing = false
	app.mu.Unlock()
}

// incrementPause пример функции, которая экспонециально контролирует время между выполнением запросов, если запросы идут подряд
// Например, factor 1.5 увеличение времени на 50% после каждой "взрывной итерации"
func IncrementPause(factor float64, maxPause time.Duration) func(currentPause time.Duration) time.Duration {
	return func(currentPause time.Duration) time.Duration {
		basePause := time.Second
		newPause := time.Duration(float64(currentPause) * factor)
		if newPause < basePause {
			return basePause
		}
		if newPause > maxPause {
			return maxPause
		}
		return newPause
	}
}
