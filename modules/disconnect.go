package modules

import (
	"math/rand"
	"net"
	"time"
)

func CheckDisconnect(target string) (string, float64) {
	reconnectDelay := getRandomDelay(2000, 8000)

	rand.Seed(time.Now().UnixNano())

	conn1, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(3))*time.Second)
	if err != nil {
		return "❌ Initial connection failed", 0
	}

	conn1.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	_, err = conn1.Read(buf)
	hasBanner := err == nil
	conn1.Close()

	time.Sleep(reconnectDelay)

	conn2, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(3))*time.Second)
	if err != nil {
		if hasBanner {
			time.Sleep(5 * time.Second)
			if checkTempBlock(target) {
				return "🚨 Server appears to be blocking our IP after connection", 90
			}
			return "🚨 Server stopped responding after disconnection (honeypot behavior)", 85
		}
		return "❌ Reconnection failed", 0
	}
	defer conn2.Close()

	conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn2.Read(buf)
	if err != nil {
		if hasBanner {
			return "⚠️ Reconnected but no banner received (suspicious)", 60
		}
		return "⚠️ Reconnected but no banner received in both attempts", 40
	}

	if hasBanner {
		return "✅ Normal behavior: successful reconnection with banner", 10
	}
	return "⚠️ Banner received only on reconnection (unusual)", 50
}

func checkTempBlock(target string) bool {
	for i := 0; i < 3; i++ {
		time.Sleep(time.Duration(1+i) * time.Second)
		conn, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err == nil {
			conn.Close()
			return false
		}
	}
	return true
}

func getRandomDelay(min, max int) time.Duration {
	if max <= min {
		return time.Duration(min) * time.Millisecond
	}
	return time.Duration(min+rand.Intn(max-min)) * time.Millisecond
}
