package logging

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// Logger encapsulates the logging functionality.
type Logger struct {
	mu     sync.RWMutex
	logger *log.Logger
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
)

// enableColors enables ANSI colors for Windows console
func enableColors() {
	if runtime.GOOS == "windows" {
		// Use windows package instead of syscall
		handle := windows.Handle(windows.STD_OUTPUT_HANDLE)
		var mode uint32
		err := windows.GetConsoleMode(handle, &mode)
		if err == nil {
			// Enable virtual terminal processing (0x0004)
			mode |= 0x0004
			_ = windows.SetConsoleMode(handle, mode)
		}
	}
}

// New creates a new Logger instance
func New(verbose bool) *Logger {
	enableColors()
	flags := 0

	output := os.Stdout
	if !verbose {
		output = os.Stderr
	}

	return &Logger{
		logger: log.New(output, "", flags),
	}
}

// colorPrintf prints a colored message
func (l *Logger) colorPrintf(color, format string, v ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	msg := fmt.Sprintf(format, v...)
	l.logger.Printf("%s%s%s", color, msg, colorReset)
}

// Printf prints a regular message
func (l *Logger) Printf(format string, v ...interface{}) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	l.logger.Printf(format, v...)
}

// Info prints an informational message
func (l *Logger) Info(format string, v ...interface{}) {
	l.Printf(format, v...)
}

// Success prints a success message in green
func (l *Logger) Success(format string, v ...interface{}) {
	l.colorPrintf(colorGreen, format, v...)
}

// Error prints an error message in red
func (l *Logger) Error(format string, v ...interface{}) {
	l.colorPrintf(colorRed, format, v...)
}

// Warning prints a warning message in yellow
func (l *Logger) Warning(format string, v ...interface{}) {
	l.colorPrintf(colorYellow, format, v...)
}

// Debug prints a debug message in blue
func (l *Logger) Debug(format string, v ...interface{}) {
	l.colorPrintf(colorBlue, format, v...)
}

// Fatal prints an error message in red and exits
func (l *Logger) Fatal(format string, v ...interface{}) {
	l.Error(format, v...)
	os.Exit(1)
}
