package modules

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

func CheckTrash(target string) (string, float64) {
	time.Sleep(time.Duration(500+rand.Intn(1500)) * time.Millisecond)
	conn, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(3))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection error: %v", err), 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	trashPayloads := [][]byte{
		[]byte("SSH-2.0-INVALID\x00\x00\x00\x02\x0A"),
		[]byte("\x00\x00\x00\x14\x06INVALID\x00\x00\x00\x00"),
		[]byte("SSH-1.99-CUSTOM\x01\x02\x03\x04"),
	}
	_, err = conn.Write(trashPayloads[rand.Intn(len(trashPayloads))])
	if err != nil {
		return fmt.Sprintf("❌ Write error: %v", err), 0
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✅ Timeout (normal for real SSH)", 10
		}
		return fmt.Sprintf("✅ Connection closed (normal): %v", err), 10
	}
	resp := strings.TrimSpace(string(buf[:n]))
	if len(resp) > 0 {
		switch {
		case strings.HasPrefix(resp, "SSH-2.0-"):
			if isKnownHoneypot(resp) {
				return fmt.Sprintf("🚨 Honeypot detected (known banner): %s", resp), 95
			}
			return fmt.Sprintf("⚠️ Responded with SSH banner to invalid data: %s", resp), 70
		case strings.Contains(resp, "Protocol mismatch"):
			return "⚠️ Got 'Protocol mismatch' response", 30
		case strings.Contains(strings.ToLower(resp), "invalid"):
			return fmt.Sprintf("⚠️ Got invalid protocol response: %s", resp), 40
		default:
			return fmt.Sprintf("⚠️ Unexpected response: %s", resp), 60
		}
	}

	return "✅ No response (normal behavior)", 10
}

func isKnownHoneypot(banner string) bool {
	honeypotSignatures := []string{
		"Cowrie", "HonSSH", "HoneyPy", "Kippo", "Dionaea", 
		"Amun", "Glastopf", "Honeyd", "MHN", "T-Pot",
	}
	for _, sig := range honeypotSignatures {
		if strings.Contains(banner, sig) {
			return true
		}
	}
	return false
}