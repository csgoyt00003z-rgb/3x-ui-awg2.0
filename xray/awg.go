package xray

// awg.go — AmneziaWG 2.0 support for the xray package.
//
// Архитектура:
//   - Xray-core НЕ поддерживает AWG обфускацию нативно.
//   - Каждый AmneziaWG inbound обслуживается отдельным процессом amneziawg-go
//     на отдельном tun-интерфейсе (awg0, awg1, …).
//   - Панель записывает конфиг в /etc/amneziawg/<iface>.conf и запускает
//     amneziawg-go + awg setconf.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
)

// ─── AWG Obfuscation параметры ────────────────────────────────────────────────

// AWGObfuscation содержит все AWG 2.0 параметры обфускации.
// При нулевых значениях ведёт себя как стандартный WireGuard.
//
// Документация: https://github.com/amnezia-vpn/amneziawg-go
type AWGObfuscation struct {
	// Junk packets — отправляются ДО рукопожатия
	Jc   int `json:"jc"`   // кол-во мусорных пакетов (рекомендуется 4-12)
	Jmin int `json:"jmin"` // мин. размер мусорного пакета в байтах
	Jmax int `json:"jmax"` // макс. размер (должен быть < MTU системы)

	// Padding — дополнительные байты к каждому типу пакета WireGuard
	S1 int `json:"s1"` // Init    (0-64 байт)
	S2 int `json:"s2"` // Response (0-64 байт)
	S3 int `json:"s3"` // Cookie  (0-64 байт)
	S4 int `json:"s4"` // Data/Transport (0-32 байт)

	// Dynamic headers (AWG 2.0) — диапазоны для uint32 type-поля пакета.
	// Формат: "x-y" (диапазон) или "z" (одно значение). НЕ должны пересекаться.
	H1 string `json:"h1"` // Init
	H2 string `json:"h2"` // Response
	H3 string `json:"h3"` // Cookie
	H4 string `json:"h4"` // Transport

	// Custom Protocol Signature (AWG 2.0) — пакеты имитации UDP-протоколов.
	// Отправляются перед каждым рукопожатием в порядке I1→I5.
	// Формат CPS: "<b 0x…> <r N> <rd N> <rc N> <t>"
	// Пустая строка = пакет не отправляется.
	// ТОЛЬКО для клиентской стороны — на сервере не нужно.
	I1 string `json:"i1"`
	I2 string `json:"i2"`
	I3 string `json:"i3"`
	I4 string `json:"i4"`
	I5 string `json:"i5"`
}

// ─── Настройки inbound'а ──────────────────────────────────────────────────────

// AWGInboundSettings — полная структура настроек AmneziaWG inbound'а.
// Хранится в поле Inbound.Settings как JSON.
type AWGInboundSettings struct {
	// MTU туннельного интерфейса (по умолчанию 1420).
	MTU int `json:"mtu"`
	// ServerAddress — IP/маска сервера внутри туннеля, напр. "10.0.0.1/24".
	ServerAddress string `json:"serverAddress"`
	// SecretKey — приватный ключ сервера (base64).
	SecretKey string `json:"secretKey"`
	// PublicKey — публичный ключ сервера (base64), вычисляется из SecretKey.
	PublicKey string `json:"publicKey"`
	// Peers — клиентские записи.
	Peers []AWGPeer `json:"peers"`
	// Obfuscation — параметры AWG 2.0.
	Obfuscation AWGObfuscation `json:"awg"`
}

// AWGPeer — запись клиента внутри настроек inbound'а.
type AWGPeer struct {
	// Приватный ключ клиента (хранится для генерации клиентского конфига).
	PrivateKey string `json:"privateKey"`
	// Публичный ключ клиента (регистрируется на сервере).
	PublicKey string `json:"publicKey"`
	// PreSharedKey — необязательный PSK (дополнительная защита).
	PreSharedKey string `json:"preSharedKey,omitempty"`
	// AllowedIPs — подсети, доступные через этот пир (на сервере обычно /32 клиента).
	AllowedIPs []string `json:"allowedIPs"`
	// Address — адрес клиента в туннеле, напр. "10.0.0.2/32".
	Address string `json:"address"`
	// DNS — DNS-серверы для клиента.
	DNS []string `json:"dns,omitempty"`
	// KeepAlive — интервал keepalive в секундах (0 = выключен).
	KeepAlive int `json:"keepAlive"`
	// Email — идентификатор клиента в панели.
	Email string `json:"email"`
	// Enable — включён ли клиент.
	Enable bool `json:"enable"`
}

// ─── Генерация ключей ────────────────────────────────────────────────────────

// GenerateAWGKeyPair генерирует пару ключей WireGuard/AWG.
// Возвращает (privateKeyBase64, publicKeyBase64, error).
func GenerateAWGKeyPair() (string, string, error) {
	privRaw := make([]byte, 32)
	if _, err := rand.Read(privRaw); err != nil {
		return "", "", fmt.Errorf("генерация приватного ключа: %w", err)
	}
	// Clamping curve25519
	privRaw[0] &= 248
	privRaw[31] &= 127
	privRaw[31] |= 64

	var pubRaw [32]byte
	curve25519.ScalarBaseMult(&pubRaw, (*[32]byte)(privRaw))

	priv := base64.StdEncoding.EncodeToString(privRaw)
	pub := base64.StdEncoding.EncodeToString(pubRaw[:])
	return priv, pub, nil
}

// ─── Генерация параметров обфускации по умолчанию ───────────────────────────

// DefaultAWGObfuscation возвращает безопасные случайные параметры AWG 2.0.
func DefaultAWGObfuscation() AWGObfuscation {
	jc := awgRandInt(4, 12)
	jmin := awgRandInt(40, 70)
	jmax := jmin + awgRandInt(20, 100)

	h := awgNonOverlappingHeaders()
	return AWGObfuscation{
		Jc:   jc,
		Jmin: jmin,
		Jmax: jmax,
		S1:   awgRandInt(15, 32),
		S2:   awgRandInt(15, 32),
		S3:   awgRandInt(15, 32),
		S4:   awgRandInt(5, 16),
		H1:   fmt.Sprintf("%d", h[0]),
		H2:   fmt.Sprintf("%d", h[1]),
		H3:   fmt.Sprintf("%d", h[2]),
		H4:   fmt.Sprintf("%d", h[3]),
		// I1-I5 оставляем пустыми — пользователь заполняет под свой протокол
	}
}

func awgRandInt(lo, hi int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	return lo + int(n.Int64())
}

func awgNonOverlappingHeaders() [4]uint32 {
	seen := map[uint32]bool{}
	var h [4]uint32
	for i := 0; i < 4; {
		n, _ := rand.Int(rand.Reader, big.NewInt(0x3FFFFFFF))
		v := uint32(n.Int64()) + 1
		if !seen[v] {
			seen[v] = true
			h[i] = v
			i++
		}
	}
	return h
}

// ─── Генерация клиентского конфига ──────────────────────────────────────────

// BuildAWGClientConf генерирует текст .conf файла для клиента Amnezia/AmneziaWG.
// serverAddr — IP или домен сервера (без порта).
// port — порт inbound'а.
func BuildAWGClientConf(settings AWGInboundSettings, peer AWGPeer, serverAddr string, port int) string {
	ob := settings.Obfuscation
	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString("# AmneziaWG 2.0 — сгенерировано 3x-ui (WINGS-N fork)\n")
	awgLine(&b, "PrivateKey", peer.PrivateKey)
	awgLine(&b, "Address", peer.Address)
	if len(peer.DNS) > 0 {
		awgLine(&b, "DNS", strings.Join(peer.DNS, ", "))
	}

	// Obfuscation params
	hasOb := ob.Jc != 0 || ob.Jmin != 0 || ob.Jmax != 0 ||
		ob.S1 != 0 || ob.S2 != 0 || ob.S3 != 0 || ob.S4 != 0 ||
		ob.H1 != "" || ob.H2 != "" || ob.H3 != "" || ob.H4 != ""

	if hasOb {
		b.WriteString("\n# AWG 2.0 параметры обфускации\n")
		if ob.Jc != 0 || ob.Jmin != 0 || ob.Jmax != 0 {
			awgIntLine(&b, "Jc", ob.Jc)
			awgIntLine(&b, "Jmin", ob.Jmin)
			awgIntLine(&b, "Jmax", ob.Jmax)
		}
		if ob.S1 != 0 { awgIntLine(&b, "S1", ob.S1) }
		if ob.S2 != 0 { awgIntLine(&b, "S2", ob.S2) }
		if ob.S3 != 0 { awgIntLine(&b, "S3", ob.S3) }
		if ob.S4 != 0 { awgIntLine(&b, "S4", ob.S4) }
		if ob.H1 != "" { awgLine(&b, "H1", ob.H1) }
		if ob.H2 != "" { awgLine(&b, "H2", ob.H2) }
		if ob.H3 != "" { awgLine(&b, "H3", ob.H3) }
		if ob.H4 != "" { awgLine(&b, "H4", ob.H4) }
	}

	// CPS пакеты I1-I5 (клиентская сторона)
	hasCPS := ob.I1 != "" || ob.I2 != "" || ob.I3 != "" || ob.I4 != "" || ob.I5 != ""
	if hasCPS {
		b.WriteString("\n# AWG 2.0 CPS пакеты (имитация UDP протоколов)\n")
		if ob.I1 != "" { awgLine(&b, "I1", ob.I1) }
		if ob.I2 != "" { awgLine(&b, "I2", ob.I2) }
		if ob.I3 != "" { awgLine(&b, "I3", ob.I3) }
		if ob.I4 != "" { awgLine(&b, "I4", ob.I4) }
		if ob.I5 != "" { awgLine(&b, "I5", ob.I5) }
	}

	b.WriteString("\n[Peer]\n")
	awgLine(&b, "PublicKey", settings.PublicKey)
	if peer.PreSharedKey != "" {
		awgLine(&b, "PresharedKey", peer.PreSharedKey)
	}
	allowedIPs := peer.AllowedIPs
	if len(allowedIPs) == 0 {
		allowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	awgLine(&b, "AllowedIPs", strings.Join(allowedIPs, ", "))
	awgLine(&b, "Endpoint", fmt.Sprintf("%s:%d", serverAddr, port))
	if peer.KeepAlive > 0 {
		awgIntLine(&b, "PersistentKeepalive", peer.KeepAlive)
	}

	return b.String()
}

func awgLine(b *strings.Builder, key, value string) {
	if value != "" {
		fmt.Fprintf(b, "%s = %s\n", key, value)
	}
}

func awgIntLine(b *strings.Builder, key string, value int) {
	fmt.Fprintf(b, "%s = %d\n", key, value)
}

// ─── Серверный конфиг (для awg setconf) ─────────────────────────────────────

// BuildAWGServerConf генерирует серверный конфиг для awg setconf.
func BuildAWGServerConf(settings AWGInboundSettings) string {
	mtu := settings.MTU
	if mtu == 0 { mtu = 1420 }
	addr := settings.ServerAddress
	if addr == "" { addr = "10.0.0.1/24" }
	ob := settings.Obfuscation

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", settings.SecretKey)
	fmt.Fprintf(&b, "Address = %s\n", addr)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)

	if ob.Jc != 0 {
		fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\n", ob.Jc, ob.Jmin, ob.Jmax)
	}
	if ob.S1 != 0 { fmt.Fprintf(&b, "S1 = %d\n", ob.S1) }
	if ob.S2 != 0 { fmt.Fprintf(&b, "S2 = %d\n", ob.S2) }
	if ob.S3 != 0 { fmt.Fprintf(&b, "S3 = %d\n", ob.S3) }
	if ob.S4 != 0 { fmt.Fprintf(&b, "S4 = %d\n", ob.S4) }
	if ob.H1 != "" { fmt.Fprintf(&b, "H1 = %s\n", ob.H1) }
	if ob.H2 != "" { fmt.Fprintf(&b, "H2 = %s\n", ob.H2) }
	if ob.H3 != "" { fmt.Fprintf(&b, "H3 = %s\n", ob.H3) }
	if ob.H4 != "" { fmt.Fprintf(&b, "H4 = %s\n", ob.H4) }
	// I1-I5 — только клиентская сторона, на сервер не кладём

	for _, peer := range settings.Peers {
		if !peer.Enable { continue }
		fmt.Fprintf(&b, "\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		if peer.PreSharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PreSharedKey)
		}
		ips := peer.AllowedIPs
		if len(ips) == 0 { ips = []string{peer.Address} }
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(ips, ", "))
	}
	return b.String()
}

// ─── AWG Daemon manager ───────────────────────────────────────────────────────

const (
	awgBin     = "amneziawg-go"
	awgToolBin = "awg"
	awgConfDir = "/etc/amneziawg"
	awgRunDir  = "/var/run/amneziawg"
)

// AWGDaemon управляет процессами amneziawg-go для каждого inbound'а.
type AWGDaemon struct {
	mu      sync.Mutex
	running map[string]*exec.Cmd
}

var globalAWGDaemon = &AWGDaemon{running: make(map[string]*exec.Cmd)}

// GetAWGDaemon возвращает глобальный singleton менеджера демонов.
func GetAWGDaemon() *AWGDaemon { return globalAWGDaemon }

// ApplyInbound записывает конфиг и (пере)запускает amneziawg-go для интерфейса.
// ifaceName: имя интерфейса, напр. "awg0".
// settingsJSON: поле Inbound.Settings.
func (d *AWGDaemon) ApplyInbound(ifaceName string, settingsJSON string) error {
	var s AWGInboundSettings
	if err := json.Unmarshal([]byte(settingsJSON), &s); err != nil {
		return fmt.Errorf("AWGDaemon.ApplyInbound: разбор настроек: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := os.MkdirAll(awgConfDir, 0700); err != nil {
		return fmt.Errorf("AWGDaemon: mkdir %s: %w", awgConfDir, err)
	}
	if err := os.MkdirAll(awgRunDir, 0755); err != nil {
		return fmt.Errorf("AWGDaemon: mkdir %s: %w", awgRunDir, err)
	}

	confPath := filepath.Join(awgConfDir, ifaceName+".conf")
	if err := os.WriteFile(confPath, []byte(BuildAWGServerConf(s)), 0600); err != nil {
		return fmt.Errorf("AWGDaemon: запись конфига %s: %w", confPath, err)
	}

	d.stop(ifaceName)

	// Поднять tun-интерфейс
	cmd := exec.Command(awgBin, "-f", ifaceName)
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("AWGDaemon: запуск amneziawg-go для %s: %w", ifaceName, err)
	}
	d.running[ifaceName] = cmd

	// Применить конфиг
	if out, err := exec.Command(awgToolBin, "setconf", ifaceName, confPath).CombinedOutput(); err != nil {
		return fmt.Errorf("AWGDaemon: awg setconf %s: %w; вывод: %s", ifaceName, err, out)
	}

	// Добавить IP-адрес на интерфейс
	mtu := s.MTU
	if mtu == 0 { mtu = 1420 }
	addr := s.ServerAddress
	if addr == "" { addr = "10.0.0.1/24" }
	_ = exec.Command("ip", "address", "add", addr, "dev", ifaceName).Run()
	_ = exec.Command("ip", "link", "set", "mtu", fmt.Sprintf("%d", mtu), "up", "dev", ifaceName).Run()

	return nil
}

// StopInbound останавливает демон для интерфейса.
func (d *AWGDaemon) StopInbound(ifaceName string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stop(ifaceName)
}

// StopAll останавливает все запущенные демоны.
func (d *AWGDaemon) StopAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for iface := range d.running {
		d.stop(iface)
	}
}

func (d *AWGDaemon) stop(ifaceName string) {
	if cmd, ok := d.running[ifaceName]; ok && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		delete(d.running, ifaceName)
	}
	_ = os.Remove(filepath.Join(awgRunDir, ifaceName+".sock"))
	_ = exec.Command("ip", "link", "del", ifaceName).Run()
}
