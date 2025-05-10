package modules

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

var knownHoneypotBanners = []string{
	"SSH-2.0-Cowrie", "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8",
	"SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3", "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7.1",
	"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7", "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2", "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1.2",
	"SSH-2.0-OpenSSH_5.1p1 Debian-5", "SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze3", "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4",
	"SSH-2.0-libssh-0.1", "SSH-2.0-dropbear", "SSH-2.0-HonSSH", "SSH-2.0-HoneyPy", "SSH-2.0-sshd-honeypot",
	"SSH-2.0-Honeyd", "SSH-2.0-ModenaSSH", "SSH-2.0-ParanoidSSH", "SSH-2.0-SSH-Honeypot", "SSH-2.0-OpenSSH_3.9p1",
	"SSH-2.0-OpenSSH_4.3p2", "SSH-2.0-OpenSSH_6.0p1", "SSH-2.0-WinSSHD", "SSH-2.0-SSHield", "SSH-2.0-SSH_Server",
	"SSH-2.0-Unknown", "SSH-2.0-Test", "SSH-2.0-MockSSH", "SSH-2.0-FakeSSH", "SSH-2.0-DummySSH", "SSH-2.0-HoneypotSSH",
}

func CheckBanner(target string) (string, float64) {
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return "❌ Connection failed", 0
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "❌ No banner received", 0
	}
	banner = strings.TrimSpace(banner)

	for _, hpBanner := range knownHoneypotBanners {
		if strings.HasPrefix(banner, hpBanner) { 
			return fmt.Sprintf("🚨 Honeypot detected: %s", banner), 95
		}
	}

	if strings.Contains(banner, "OpenSSH") {
		if strings.Contains(banner, "OpenSSH_3") || strings.Contains(banner, "OpenSSH_4") {
			return fmt.Sprintf("⚠️ Suspicious banner (old OpenSSH): %s", banner), 70
		}
	}
	return fmt.Sprintf("📜 SSH Banner (may not honeypot): %s", banner), 20
}
