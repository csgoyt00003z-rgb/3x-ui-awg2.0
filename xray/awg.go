// ============================================================
// FILE: xray/awg.go
// Место: добавить новый файл в пакет xray
// ============================================================
package xray

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/WINGS-N/3x-ui/v2/database/model"
	"github.com/WINGS-N/3x-ui/v2/logger"
)

const (
	awgBinary  = "/usr/local/bin/amneziawg-go"
	awgConfDir = "/etc/amneziawg"
)

// awgSettings — внутренняя структура для десериализации
type awgSettings struct {
	Mtu          int          `json:"mtu"`
	PrivateKey   string       `json:"privateKey"`
	ServerPubKey string       `json:"serverPubKey"`
	Jc           int          `json:"jc"`
	JMin         int          `json:"jMin"`
	JMax         int          `json:"jMax"`
	S1           int          `json:"s1"`
	S2           int          `json:"s2"`
	S3           int          `json:"s3"`
	S4           int          `json:"s4"`
	H1           string       `json:"h1"`
	H2           string       `json:"h2"`
	H3           string       `json:"h3"`
	H4           string       `json:"h4"`
	I1           string       `json:"i1"`
	I2           string       `json:"i2"`
	I3           string       `json:"i3"`
	I4           string       `json:"i4"`
	I5           string       `json:"i5"`
	Peers        []awgPeerCfg `json:"peers"`
}

type awgPeerCfg struct {
	PublicKey  string   `json:"publicKey"`
	PrivateKey string   `json:"privateKey"`
	Address    string   `json:"address"`
	AllowedIPs []string `json:"allowedIPs"`
	Email      string   `json:"email"`
	Enable     bool     `json:"enable"`
}

// LaunchAWGDaemon запускает amneziawg-go для данного inbound.
// Генерирует серверный конфиг и поднимает интерфейс awg<port>.
func LaunchAWGDaemon(inbound model.Inbound) error {
	if _, err := os.Stat(awgBinary); os.IsNotExist(err) {
		return fmt.Errorf("amneziawg-go not found at %s; install it first", awgBinary)
	}

	cfg := &awgSettings{}
	if err := json.Unmarshal([]byte(inbound.Settings), cfg); err != nil {
		return fmt.Errorf("parse awg settings: %w", err)
	}

	ifName := fmt.Sprintf("awg%d", inbound.Port)

	if err := os.MkdirAll(awgConfDir, 0700); err != nil {
		return fmt.Errorf("mkdir awgConfDir: %w", err)
	}

	confPath := fmt.Sprintf("%s/%s.conf", awgConfDir, ifName)
	confData := buildAWGServerConf(cfg, inbound.Port)

	if err := os.WriteFile(confPath, []byte(confData), 0600); err != nil {
		return fmt.Errorf("write awg conf: %w", err)
	}

	// Удалить интерфейс если существует
	exec.Command("ip", "link", "del", ifName).Run()

	// Запустить amneziawg-go в фоне
	cmd := exec.Command(awgBinary, ifName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start amneziawg-go: %w", err)
	}
	logger.Infof("amneziawg-go started for interface %s (pid %d)", ifName, cmd.Process.Pid)

	// Применить конфиг
	if err := exec.Command("awg", "setconf", ifName, confPath).Run(); err != nil {
		return fmt.Errorf("awg setconf: %w", err)
	}

	// Поднять интерфейс и назначить адрес
	exec.Command("ip", "link", "set", ifName, "up").Run()
	exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", ifName).Run()

	// Включить маршрутизацию
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	return nil
}

// StopAWGDaemon останавливает интерфейс amneziawg-go
func StopAWGDaemon(inbound model.Inbound) error {
	ifName := fmt.Sprintf("awg%d", inbound.Port)
	sockPath := fmt.Sprintf("/var/run/amneziawg/%s.sock", ifName)

	exec.Command("ip", "link", "del", ifName).Run()
	os.Remove(sockPath)

	return nil
}

// buildAWGServerConf формирует серверный конфиг.
// Сервер НЕ использует Jc, I1-I5 (только клиентские параметры).
// Сервер использует S1-S4, H1-H4 (должны совпадать с клиентом).
func buildAWGServerConf(cfg *awgSettings, port int) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", cfg.PrivateKey))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", port))

	// Padding — обе стороны
	if cfg.S1 > 0 { sb.WriteString(fmt.Sprintf("S1 = %d\n", cfg.S1)) }
	if cfg.S2 > 0 { sb.WriteString(fmt.Sprintf("S2 = %d\n", cfg.S2)) }
	if cfg.S3 > 0 { sb.WriteString(fmt.Sprintf("S3 = %d\n", cfg.S3)) }
	if cfg.S4 > 0 { sb.WriteString(fmt.Sprintf("S4 = %d\n", cfg.S4)) }

	// Header ranges — обе стороны
	if cfg.H1 != "" { sb.WriteString(fmt.Sprintf("H1 = %s\n", cfg.H1)) }
	if cfg.H2 != "" { sb.WriteString(fmt.Sprintf("H2 = %s\n", cfg.H2)) }
	if cfg.H3 != "" { sb.WriteString(fmt.Sprintf("H3 = %s\n", cfg.H3)) }
	if cfg.H4 != "" { sb.WriteString(fmt.Sprintf("H4 = %s\n", cfg.H4)) }

	// Peers
	for _, peer := range cfg.Peers {
		if !peer.Enable {
			continue
		}
		sb.WriteString("\n[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", ip))
			}
		} else if peer.Address != "" {
			// Берём адрес без маски подсети и добавляем /32
			addr := strings.Split(peer.Address, "/")[0]
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s/32\n", addr))
		}
	}

	return sb.String()
}

// GenAWGClientConf генерирует .conf файл для конкретного клиента.
// Включает ВСЕ AWG 2.0 параметры, в том числе I1-I5.
func GenAWGClientConf(inbound model.Inbound, email, serverHost string) (string, error) {
	cfg := &awgSettings{}
	if err := json.Unmarshal([]byte(inbound.Settings), cfg); err != nil {
		return "", fmt.Errorf("parse awg settings: %w", err)
	}

	var peer *awgPeerCfg
	for i := range cfg.Peers {
		if cfg.Peers[i].Email == email {
			peer = &cfg.Peers[i]
			break
		}
	}
	if peer == nil {
		return "", fmt.Errorf("peer with email %q not found", email)
	}

	endpoint := fmt.Sprintf("%s:%d", serverHost, inbound.Port)
	mtu := cfg.Mtu
	if mtu == 0 {
		mtu = 1420
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", peer.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", peer.Address))
	sb.WriteString("DNS = 1.1.1.1, 1.0.0.1\n")
	sb.WriteString(fmt.Sprintf("MTU = %d\n", mtu))

	// Junk packets (только клиент)
	if cfg.Jc > 0 {
		sb.WriteString(fmt.Sprintf("Jc = %d\n", cfg.Jc))
		sb.WriteString(fmt.Sprintf("Jmin = %d\n", cfg.JMin))
		sb.WriteString(fmt.Sprintf("Jmax = %d\n", cfg.JMax))
	}

	// Padding (обе стороны)
	if cfg.S1 > 0 { sb.WriteString(fmt.Sprintf("S1 = %d\n", cfg.S1)) }
	if cfg.S2 > 0 { sb.WriteString(fmt.Sprintf("S2 = %d\n", cfg.S2)) }
	if cfg.S3 > 0 { sb.WriteString(fmt.Sprintf("S3 = %d\n", cfg.S3)) }
	if cfg.S4 > 0 { sb.WriteString(fmt.Sprintf("S4 = %d\n", cfg.S4)) }

	// Headers (обе стороны)
	if cfg.H1 != "" { sb.WriteString(fmt.Sprintf("H1 = %s\n", cfg.H1)) }
	if cfg.H2 != "" { sb.WriteString(fmt.Sprintf("H2 = %s\n", cfg.H2)) }
	if cfg.H3 != "" { sb.WriteString(fmt.Sprintf("H3 = %s\n", cfg.H3)) }
	if cfg.H4 != "" { sb.WriteString(fmt.Sprintf("H4 = %s\n", cfg.H4)) }

	// Custom signature packets — AWG 2.0 (только клиент)
	if cfg.I1 != "" { sb.WriteString(fmt.Sprintf("I1 = %s\n", cfg.I1)) }
	if cfg.I2 != "" { sb.WriteString(fmt.Sprintf("I2 = %s\n", cfg.I2)) }
	if cfg.I3 != "" { sb.WriteString(fmt.Sprintf("I3 = %s\n", cfg.I3)) }
	if cfg.I4 != "" { sb.WriteString(fmt.Sprintf("I4 = %s\n", cfg.I4)) }
	if cfg.I5 != "" { sb.WriteString(fmt.Sprintf("I5 = %s\n", cfg.I5)) }

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", cfg.ServerPubKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", endpoint))
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String(), nil
}
