package modules

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func CheckHelp(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return "❌ Connection refused.", 0
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("help\r\n"))

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "✅ Server ignored 'help'", 10
	}

	response := strings.TrimSpace(string(buf[:n]))
	
	if strings.Contains(strings.ToLower(response), "cowrie") || 
	   strings.Contains(strings.ToLower(response), "kippo") {
		return fmt.Sprintf("☣️ Trap! Answered: %s", response), 99
	}

	if strings.Contains(response, "Available commands") || 
	   len(response) > 100 {
		return fmt.Sprintf("⚠️ Suspicious! Answer: %s", response), 85
	}

	if len(response) > 0 {
		return fmt.Sprintf("⚠️ Answer on 'help': %s", response), 50
	}

	return "❔The server is silent on 'help'", 20
}