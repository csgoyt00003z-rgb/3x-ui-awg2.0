package sub

// awg_sub.go — AmneziaWG 2.0: генерация клиентских конфигов.
// Добавь этот файл в директорию sub/.
//
// Также нужно добавить в subService.go метод GetLink() ветку для AmneziaWG:
//
//   case model.AmneziaWG:
//       return s.genAWGLink(inbound, email)
//
// И добавить метод genAWGLink к SubService (пример ниже в BuildAWGSubLink).

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/WINGS-N/3x-ui/v2/database/model"
	"github.com/WINGS-N/3x-ui/v2/xray"
)

// BuildAWGSubLink возвращает AWG-конфиг в виде строки base64 (формат "awg://<base64>")
// либо пустую строку если клиент не найден.
// host — адрес сервера (берётся из запроса).
//
// Вызывай это из GetLink() в subService.go:
//
//   case model.AmneziaWG:
//       return BuildAWGSubLink(inbound, email, s.address)
func BuildAWGSubLink(inbound *model.Inbound, email, serverHost string) string {
	conf, err := GenAWGClientConf(inbound, email, serverHost)
	if err != nil || conf == "" {
		return ""
	}
	// Amnezia-клиенты принимают conf-файл напрямую (не как URI).
	// Для subscription-совместимости возвращаем пустую строку —
	// клиентский конфиг скачивается отдельно через /server/awg/clientconf.
	// Если нужен URI: закомментируй return "" и раскомментируй строки ниже.
	//
	// encoded := base64.StdEncoding.EncodeToString([]byte(conf))
	// return "awg://" + encoded + "#" + url.QueryEscape(email)
	_ = conf
	return ""
}

// GenAWGClientConf генерирует текст .conf файла для конкретного клиента.
// serverHost — IP или домен сервера (без порта).
func GenAWGClientConf(inbound *model.Inbound, email, serverHost string) (string, error) {
	if inbound.Protocol != model.AmneziaWG {
		return "", fmt.Errorf("GenAWGClientConf: протокол %s не является amneziawg", inbound.Protocol)
	}

	var settings xray.AWGInboundSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		return "", fmt.Errorf("GenAWGClientConf: разбор settings: %w", err)
	}

	// Ищем пира по email
	var peer *xray.AWGPeer
	for i := range settings.Peers {
		if strings.EqualFold(settings.Peers[i].Email, email) {
			peer = &settings.Peers[i]
			break
		}
	}
	if peer == nil {
		return "", fmt.Errorf("GenAWGClientConf: клиент %q не найден", email)
	}
	if !peer.Enable {
		return "", fmt.Errorf("GenAWGClientConf: клиент %q отключён", email)
	}

	conf := xray.BuildAWGClientConf(settings, *peer, serverHost, inbound.Port)
	return conf, nil
}
