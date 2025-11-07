package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
)

// Level represents the logging level
type Level int

const (
	LevelQuiet Level = iota // No logs
	LevelError              // Only errors
	LevelInfo               // Info and errors
	LevelDebug              // Debug, info, and errors
	LevelTrace              // All logs including trace
)

var (
	globalLevel Level = LevelInfo
	globalMu    sync.RWMutex
)

// SetLevel sets the global logging level
func SetLevel(level string) {
	globalMu.Lock()
	defer globalMu.Unlock()
	
	switch level {
	case "quiet":
		globalLevel = LevelQuiet
	case "error":
		globalLevel = LevelError
	case "info":
		globalLevel = LevelInfo
	case "debug":
		globalLevel = LevelDebug
	case "trace":
		globalLevel = LevelTrace
	default:
		// Default to debug for backwards compatibility
		globalLevel = LevelDebug
	}
}

// GetLevel returns the current logging level
func GetLevel() Level {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLevel
}

// Logger provides level-based logging
type Logger struct {
	prefix string
}

// New creates a new logger with an optional prefix
func New(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// shouldLog checks if a message at the given level should be logged
func (l *Logger) shouldLog(level Level) bool {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return level <= globalLevel
}

// formatMessage formats the message with level and prefix if present
func (l *Logger) formatMessage(level string, format string, args ...interface{}) string {
	msg := fmt.Sprintf(format, args...)
	if l.prefix != "" {
		return fmt.Sprintf("[%s][%s] %s", level, l.prefix, msg)
	}
	return fmt.Sprintf("[%s] %s", level, msg)
}

// Error logs error-level messages (always shown unless quiet)
func (l *Logger) Error(format string, args ...interface{}) {
	if !l.shouldLog(LevelError) {
		return
	}
	msg := l.formatMessage("ERROR", format, args...)
	log.Printf("%s", msg)
}

// Info logs info-level messages
func (l *Logger) Info(format string, args ...interface{}) {
	if !l.shouldLog(LevelInfo) {
		return
	}
	msg := l.formatMessage("INFO", format, args...)
	log.Printf("%s", msg)
}

// Debug logs debug-level messages
func (l *Logger) Debug(format string, args ...interface{}) {
	if !l.shouldLog(LevelDebug) {
		return
	}
	msg := l.formatMessage("DEBUG", format, args...)
	log.Printf("%s", msg)
}

// Trace logs trace-level messages (most verbose)
func (l *Logger) Trace(format string, args ...interface{}) {
	if !l.shouldLog(LevelTrace) {
		return
	}
	msg := l.formatMessage("TRACE", format, args...)
	log.Printf("%s", msg)
}

// Fatal logs a fatal error and exits (always logged, even in quiet mode)
func (l *Logger) Fatal(format string, args ...interface{}) {
	msg := l.formatMessage("FATAL", format, args...)
	log.Printf("%s", msg)
	os.Exit(1)
}

// Fatalf logs a fatal error with formatting and exits (always logged, even in quiet mode)
func (l *Logger) Fatalf(format string, args ...interface{}) {
	msg := l.formatMessage("FATAL", format, args...)
	log.Fatalf("%s", msg)
}

// Package-level convenience functions using default logger
var defaultLogger = New("")

// SetLevel sets the global logging level (package-level)
func SetGlobalLevel(level string) {
	SetLevel(level)
}

// Error logs error-level messages
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// Info logs info-level messages
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Debug logs debug-level messages
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Trace logs trace-level messages
func Trace(format string, args ...interface{}) {
	defaultLogger.Trace(format, args...)
}

// Fatal logs a fatal error and exits
func Fatal(format string, args ...interface{}) {
	defaultLogger.Fatal(format, args...)
}

// Fatalf logs a fatal error with formatting and exits
func Fatalf(format string, args ...interface{}) {
	defaultLogger.Fatalf(format, args...)
}

