package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

var suspiciousKexAlgs = []string{
	"diffie-hellman-group-exchange-sha1",
	"diffie-hellman-group1-sha1",
	"diffie-hellman-group14-sha1",
	"ecdh-sha2-nistp256",
	"gss-group1-sha1-",
}

var suspiciousCiphers = []string{
	"3des-cbc", "blowfish-cbc", "cast128-cbc",
	"aes128-cbc", "aes192-cbc", "aes256-cbc",
	"arcfour", "arcfour128", "arcfour256",
}

var suspiciousMACs = []string{
	"hmac-md5", "hmac-sha1", "hmac-md5-96",
	"hmac-sha1-96", "umac-64@openssh.com",
}

var suspiciousHostKeys = []string{
	"ssh-dss", "ssh-rsa", "rsa-sha1",
	"x509v3-sign-rsa", "x509v3-sign-dss",
}

var suspiciousCompressions = []string{
	"zlib", "zlib@openssh.com", "none",
}

var knownHoneypotBanners3 = []string{
	"SSH-2.0-Cowrie",
	"SSH-2.0-HonSSH",
	"SSH-2.0-HoneyPy",
	"SSH-2.0-ModenaSSH",
	"SSH-2.0-ParanoidSSH",
	"SSH-2.0-SSH-Honeypot",
	"SSH-2.0-MockSSH",
	"SSH-2.0-FakeSSH",
}

func AnalyzeSSHParams(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection failed: %v", err), 0
	}
	defer conn.Close()
	clientBanner := fmt.Sprintf("SSH-2.0-OpenSSH_%d.%dp1\r\n", 7+rand.Intn(2), rand.Intn(10))
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(clientBanner)); err != nil {
		return fmt.Sprintf("❌ Failed to send client banner: %v", err), 0
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	serverBanner := make([]byte, 256)
	n, err := conn.Read(serverBanner)
	if err != nil {
		return fmt.Sprintf("❌ Failed to read server banner: %v", err), 0
	}
	serverBannerStr := string(bytes.TrimRight(serverBanner[:n], "\r\n"))
	if err := sendKexInit(conn); err != nil {
		return fmt.Sprintf("❌ Failed to send KEX: %v", err), 0
	}
	serverParams, err := readServerParams(conn)
	if err != nil {
		return fmt.Sprintf("❌ Failed to read params: %v", err), 0
	}
	probability := calculateProbability(serverParams, serverBannerStr)
	summary := generateSummary(serverParams, serverBannerStr, probability)

	return summary, probability
}

func sendKexInit(conn net.Conn) error {
	cookie := make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteByte(0x00) 
	buf.Write(cookie)   
	algorithms := []string{
		"curve25519-sha256", "ext-info-c",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
	}
	for _, algo := range algorithms {
		buf.Write([]byte(algo))
		buf.WriteByte(0)
	}
	if rand.Intn(2) == 0 {
		buf.Write([]byte{0x00, 0x00, 0x00})
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	jitter := time.Duration(200 + rand.Intn(1000)) * time.Millisecond
	time.Sleep(jitter)
	return nil
}

func readServerParams(conn net.Conn) (map[string]string, error) {
	params := make(map[string]string)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	response := buf[:n]
	if len(response) > 5 && response[0] == 0x00 && response[1] == 0x00 {
		params["kex_algorithms"] = parseSSHString(response[20:])
		params["server_host_key_algorithms"] = parseSSHString(response[40:])
		params["encryption_algorithms"] = parseSSHString(response[60:])
		params["mac_algorithms"] = parseSSHString(response[80:])
		params["compression_algorithms"] = parseSSHString(response[100:])
	}

	return params, nil
}

func parseSSHString(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	length := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(length)+4 {
		return ""
	}
	return string(data[4 : 4+length])
}

func calculateProbability(params map[string]string, banner string) float64 {
	score := 0.0
	for _, hpBanner := range knownHoneypotBanners3 {
		if strings.Contains(banner, hpBanner) {
			score += 95
			break
		}
	}
	if strings.Contains(banner, "OpenSSH") {
		re := regexp.MustCompile(`OpenSSH[_\-](\d+)`)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 1 {
			if ver, err := strconv.Atoi(matches[1]); err == nil && ver < 7 {
				score += 60 - float64(ver)*5
			}
		}
	}
	checkParams := map[string]struct {
		list  []string
		score float64
	}{
		"kex_algorithms":               {suspiciousKexAlgs, 15},
		"server_host_key_algorithms":   {suspiciousHostKeys, 20},
		"encryption_algorithms":        {suspiciousCiphers, 15},
		"mac_algorithms":               {suspiciousMACs, 10},
		"compression_algorithms":       {suspiciousCompressions, 5},
	}

	for paramName, check := range checkParams {
		if val, ok := params[paramName]; ok {
			for _, susItem := range check.list {
				if strings.Contains(val, susItem) {
					score += check.score
				}
			}
		}
	}
	if strings.Contains(params["kex_algorithms"], "diffie-hellman-group1-sha1") {
		score += 30
	}
	if strings.Contains(params["server_host_key_algorithms"], "ssh-dss") {
		score += 40
	}
	if strings.Contains(params["encryption_algorithms"], "none") {
		score += 50
	}

	if score > 100 {
		score = 100
	}
	return score
}

func generateSummary(params map[string]string, banner string, probability float64) string {
	var issues []string

	for _, hpBanner := range knownHoneypotBanners3 {
		if strings.Contains(banner, hpBanner) {
			issues = append(issues, "known honeypot")
			break
		}
	}

	checkParams := map[string]string{
		"kex_algorithms":             "weak kex",
		"server_host_key_algorithms": "weak host key",
		"encryption_algorithms":      "weak cipher",
		"mac_algorithms":             "weak MAC",
		"compression_algorithms":     "weak compression",
	}

	for paramName, issueDesc := range checkParams {
		if val, ok := params[paramName]; ok {
			for _, algo := range suspiciousKexAlgs {
				if strings.Contains(val, algo) {
					issues = append(issues, issueDesc)
					break
				}
			}
		}
	}

	var summary strings.Builder
	summary.WriteString("Ready: ")

	switch {
	case probability > 80:
		summary.WriteString("🚨 HIGH RISK")
	case probability > 50:
		summary.WriteString("⚠️ MEDIUM RISK")
	default:
		summary.WriteString("✅ LOW RISK")
	}

	if len(issues) > 0 {
		summary.WriteString(" (")
		summary.WriteString(strings.Join(issues, ", "))
		summary.WriteString(")")
	} else {
		summary.WriteString(" (no issues)")
	}

	summary.WriteString(fmt.Sprintf(" [%.0f%%]", probability))

	return summary.String()
}