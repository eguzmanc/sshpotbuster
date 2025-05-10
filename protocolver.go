package modules

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func CheckProtocolVersion(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return "❌ Connection failed", 0
	}
	defer conn.Close()

	conn.Write([]byte("SSH-1.99-DickClient\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	response := string(buf[:n])

	switch {
	case strings.Contains(response, "SSH-2.0"):
		return "✅ SSH-2.0 only (Normal)", 10
	case strings.Contains(response, "SSH-1.99"):
		return "🚨 Accepts fake version (Honeypot!)", 100
	default:
		return fmt.Sprintf("❔Unknown response: %s", response), 50
	}
}