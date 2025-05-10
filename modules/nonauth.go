package modules

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

func CheckNoneAuth(target string) (string, float64) {
	time.Sleep(getRandomDelay(1000, 5000)) // 1-5 секунд
	conn, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(4))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection failed: %v", err), 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	clientBanners := []string{
		"SSH-2.0-OpenSSH_8.9p1",
		"SSH-2.0-PuTTY_Release_0.76",
		"SSH-2.0-libssh-0.9.5",
	}
	banner := clientBanners[rand.Intn(len(clientBanners))] + "\r\n"
	conn.Write([]byte(banner))
	time.Sleep(getRandomDelay(200, 1000))
	noneAuthPacket := []byte{
		0x00, 0x00, 0x00, 0x14, 
		0x06,                     
		0x00, 0x00, 0x00, 0x04,  
		0x6e, 0x6f, 0x6e, 0x65, 
	}

	randByte, _ := rand.Int(rand.Reader, big.NewInt(256))
	noneAuthPacket[5] = byte(randByte.Int64() % 16) 
	conn.Write(noneAuthPacket)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✅ Timeout (normal behavior)", 10
		}
		return fmt.Sprintf("✅ Connection closed (normal): %v", err), 10
	}

	response := buf[:n]

	honeypotIndicators := []struct {
		pattern    []byte
		confidence int
		message    string
	}{
		{[]byte{0x00, 0x00, 0x00, 0x34, 0x06}, 95, "🚨 Honeypot: Full protocol exchange"},
		{[]byte("cowrie"), 99, "☣️ Cowrie honeypot detected"},
		{[]byte("kippo"), 99, "☣️ Kippo honeypot detected"},
		{[]byte("invalid"), 80, "⚠️ Unexpected: Invalid protocol response"},
		{[]byte("service not available"), 85, "⚠️ Suspicious: Service not available"},
	}

	for _, indicator := range honeypotIndicators {
		if bytes.Contains(response, indicator.pattern) {
			return fmt.Sprintf("%s (response: %x)", indicator.message, response), float64(indicator.confidence)
		}
	}

	switch {
	case n == 0:
		return "✅ No response (normal)", 5
	case response[0] == 0x05: // SSH_MSG_SERVICE_ACCEPT
		return "⚠️ Accepted 'none' auth (very suspicious)", 90
	case response[0] == 0x02: // SSH_MSG_DISCONNECT
		return "✅ Protocol error (normal)", 10
	default:
		return fmt.Sprintf("⚠️ Unexpected response: %x", response), 60
	}
}

func getRandomDelay(min, max int) time.Duration {
	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return time.Duration(min+int(randNum.Int64())) * time.Millisecond
}