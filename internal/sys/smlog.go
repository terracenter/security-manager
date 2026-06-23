package sys

import (
	"fmt"
	"os"
	"time"
)

const logPath = "/var/log/security-manager-ng.log"

// SMLogger gestiona logging dual: pantalla + archivo.
// Si no puede abrir el archivo (sin permisos), continúa solo con pantalla.
type SMLogger struct {
	file     *os.File
	hasFile  bool
	infoMode bool // true = verbose (pantalla + log), false = quiet (solo pantalla)
}

// NewLogger inicializa el logger.
// Intenta abrir /var/log/security-manager-ng.log en modo append.
// Si falla (permisos, ruta no existe), continúa solo con pantalla.
func NewLogger() *SMLogger {
	logger := &SMLogger{
		infoMode: false,
		hasFile:  false,
	}

	// Intentar abrir archivo de log
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err == nil {
		logger.file = f
		logger.hasFile = true
	}
	// Si falla, simplemente continúa sin archivo

	return logger
}

// Close cierra el archivo de log si está abierto.
func (l *SMLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Screen imprime un mensaje SOLO en pantalla (sin log).
func (l *SMLogger) Screen(msg string) {
	fmt.Printf("%s\n", msg)
}

// Info imprime un mensaje en pantalla y lo registra en el log con nivel [INFO].
func (l *SMLogger) Info(msg string) {
	fmt.Printf("%s\n", msg)
	if l.hasFile {
		l.writeLog("INFO", msg)
	}
}

// Warn imprime un mensaje de advertencia en pantalla y lo registra en el log con nivel [WARN].
func (l *SMLogger) Warn(msg string) {
	fmt.Printf("  [warn] %s\n", msg)
	if l.hasFile {
		l.writeLog("WARN", msg)
	}
}

// Error imprime un mensaje amigable en pantalla y registra ambos (amigable + técnico) en el log.
// friendly: mensaje que ve el usuario (ej: "No se pudo aplicar el ruleset")
// technical: detalle técnico para el log (ej: salida cruda de nft -c)
func (l *SMLogger) Error(friendly, technical string) {
	fmt.Printf("  ✗ %s\n", friendly)
	if l.hasFile {
		l.writeLog("ERROR", friendly)
		if technical != "" {
			l.writeLog("ERROR_DETAIL", technical)
		}
	}
}

// Technical registra un mensaje SOLO en el log (output crudo de comandos, detalles internos).
// No se imprime en pantalla.
func (l *SMLogger) Technical(detail string) {
	if l.hasFile {
		l.writeLog("TECHNICAL", detail)
	}
}

// writeLog escribe una línea en el archivo de log con timestamp.
// Formato: 2026-06-22 20:01:34 [LEVEL] mensaje
func (l *SMLogger) writeLog(level, msg string) {
	if l.file == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s [%s] %s\n", timestamp, level, msg)
	_, _ = l.file.WriteString(line) // Ignorar errores de escritura — no bloquean ejecución
}
