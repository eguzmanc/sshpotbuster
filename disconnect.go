package modules

import (
	"net"
	"time"
)

func CheckDisconnect(target string) (string, float64) {
	conn1, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return "❌ Error during connection. (Connect unsuccesful)", 0
	}
	conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	_, err = conn1.Read(buf)
	hasBanner := err == nil
	conn1.Close()
	time.Sleep(3 * time.Second)
	conn2, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		if hasBanner {
			return "🚨 Server stopped responding after disconnection (possible honeypot)", 85
		}
		return "❌ Reconnection error", 0
	}
	defer conn2.Close()
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn2.Read(buf)
	if err != nil {
		return "⚠️ Reconnection successful, but banner not received", 40
	}
	if hasBanner {
		return "✅ Successful reconnection with banner received", 20
	}
	return "⚠️ Reconnection successful, but banner not received in both cases", 50
}