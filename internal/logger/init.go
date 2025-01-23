package logger

import (
	"fmt"
	"os"
	"strconv"
)

func NewLogger() (Logger, error) {
	loggerType := os.Getenv("logger")
	loggerTypeInt, err := strconv.Atoi(loggerType)
	if err != nil {
		return nil, err
	}

	switch loggerTypeInt {
	case 0:
		return NewConsoleLogger(), nil
	case 1:
		logger, err := NewFileLogger("/logs/")
		return logger, err
	case 2:
		logger, err := NewCombinedLogger("/logs/")
		return logger, err
	default:
		return nil, fmt.Errorf("wrong n - %d. N can be only: 0,1,2", loggerTypeInt)
	}
}
