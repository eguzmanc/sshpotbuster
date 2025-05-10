package modules

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func CheckInvalidCommand(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return "❌ Connection error.", 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	commands := []string{
		"HELLO\r\n",         
		"SSH-INCORRECT\r\n", 
		"\x00\x00\x00\x00\r\n", 
	}

	var responses []string

	for _, cmd := range commands {
		_, err := conn.Write([]byte(cmd))
		if err != nil {
			continue
		}

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			responses = append(responses, strings.TrimSpace(string(buf[:n])))
		}
	}

	if len(responses) == 0 {
		return "✅ Normal behavior: no response to invalid commands", 10
	}
	fullResponse := strings.Join(responses, " | ")

	honeypotIndicators := []string{
		"SSH-2.0",          
		"invalid",           
		"protocol",         
		"unrecognized",     
		"command",          
		"hello",            
		"cowrie",           
		"kippo",            
	}
	detectedIndicators := 0
	for _, indicator := range honeypotIndicators {
		if strings.Contains(strings.ToLower(fullResponse), strings.ToLower(indicator)) {
			detectedIndicators++
		}
	}
	confidence := 0
	message := fmt.Sprintf("⚠️ Response to non-standard commands: %s", fullResponse)

	switch {
	case detectedIndicators >= 3:
		confidence = 95
		message = "🚨 Maybe honeypot: " + message
	case detectedIndicators >= 1:
		confidence = 70
		message = "⚠️ suspicious behavior: " + message
	default:
		confidence = 30
	}
	return message, float64(confidence)
}