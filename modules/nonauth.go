package modules

import (
	"math/rand"
	"net"
	"time"
)

func CheckNoneAuth(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, time.Duration(2 + rand.Intn(3)) * time.Second)
	if err != nil {
		return "❌ Connection failed (timeout)", 0
	}
	defer conn.Close()


	payload := []byte{
		0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x0d, 0x0a, 
		0x00, 0x00, 0x00, 0x12, 
		0x06, 0x14, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x6f, 0x6e, 0x65, 
	}

	conn.SetDeadline(time.Now().Add(1 * time.Second))
	conn.Write(payload)
	buf := make([]byte, 32)
	n, _ := conn.Read(buf)

	switch {
	case n == 0:
		return "✅ Silent drop (Normal)", 5 
	case buf[0] == 0x02:
		return "✅ Protocol error (Normal)", 10 
	default:
		return "🚨 Responded to broken packet (Honeypot!)", 98
	}
}
