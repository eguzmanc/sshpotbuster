package modules

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

func CheckHelp(target string) (string, float64) {
	time.Sleep(getRandomDelay2(1000, 5000))

	rand.Seed(time.Now().UnixNano())

	conn, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(4))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection error: %v", err), 0
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("SSH-2.0-9.53b\r\n"))
	if err != nil {
		return fmt.Sprintf("❌ Failed to send client header: %v", err), 0
	}

	time.Sleep(getRandomDelay2(200, 1000))

	_, err = conn.Write([]byte("\x00\x00\x00\x04\x0Ahelp"))
	if err != nil {
		return fmt.Sprintf("❌ Failed to send help command: %v", err), 0
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✅ Normal: No response to 'help'", 10
		}
		return fmt.Sprintf("✅ Connection closed (normal): %v", err), 10
	}

	response := strings.TrimSpace(string(buf[:n]))

	honeypotPatterns := []struct {
		pattern    string
		confidence int
		message    string
	}{
		{"cowrie", 99, "☣️ Cowrie honeypot detected"},
		{"kippo", 99, "☣️ Kippo honeypot detected"},
		{"honeypot", 95, "☣️ Generic honeypot detected"},
		{"available commands", 90, "⚠️ Suspicious: Available commands list"},
		{"help", 80, "⚠️ Suspicious: Help response"},
		{"invalid", 60, "⚠️ Unexpected: Invalid command response"},
	}

	for _, p := range honeypotPatterns {
		if strings.Contains(strings.ToLower(response), p.pattern) {
			return fmt.Sprintf("%s: %s", p.message, response), float64(p.confidence)
		}
	}

	switch {
	case len(response) > 200:
		return fmt.Sprintf("⚠️ Suspiciously long response: %s", truncate(response, 100)), 85
	case len(response) > 0:
		return fmt.Sprintf("⚠️ Unexpected response: %s", response), 50
	default:
		return "✅ Normal: No response to 'help'", 10
	}
}

func getRandomDelay2(min, max int) time.Duration {
	if max <= min {
		return time.Duration(min) * time.Millisecond
	}
	return time.Duration(min+rand.Intn(max-min)) * time.Millisecond
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
