package modules

import (
	"fmt"
	"net"
	"time"
)

func CheckDelay(target string) (float64, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	delay := time.Since(start)
	return float64(delay.Microseconds()) / 1000, nil 
}

func RunDelayCheck(target string) (string, float64) {
	delay, err := CheckDelay(target)
	if err != nil {
		return "❌ Connect error.", 0
	}
	if delay > 500 { 
		return fmt.Sprintf("⏱️ Delay: %.2f ms", delay), 100
	}
	return fmt.Sprintf("⏱️ Recorded delay: %.2f ms", delay), 35
}
