package modules

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func CheckTrash(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return "❌ Connection error", 0
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	conn.Write([]byte("AAAA\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "✅ No response to trash (normal for real SSH)", 10 
	}

	resp := strings.TrimSpace(string(buf[:n]))

	if len(resp) > 0 {
		if strings.HasPrefix(resp, "SSH-2.0-") {
			return fmt.Sprintf("🚨 Honeypot likely (responded with SSH banner to trash): %s", resp), 95
		}
		if strings.Contains(resp, "Protocol mismatch") {
			return fmt.Sprintf("⚠️ Got 'Protocol mismatch' (normal SSH behavior): %s", resp), 20
		}
		return fmt.Sprintf("⚠️ Unexpected response to trash: %s", resp), 80
	}

	return "✅ No response to trash probes (normal)", 10
}