#!/bin/bash
# install_awg.sh — Установка amneziawg-go и awg-tools для 3x-ui AWG 2.0
#
# Использование:
#   bash install_awg.sh
#
# Запускается автоматически из install.sh если протокол amneziawg активен.

set -e

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

AWG_GO_REPO="amnezia-vpn/amneziawg-go"
AWG_TOOLS_REPO="amnezia-vpn/amneziawg-tools"
INSTALL_DIR="/usr/local/bin"
TMP_DIR=$(mktemp -d)

# ─── Определение архитектуры ──────────────────────────────────────────────────

detect_arch() {
    case "$(uname -m)" in
        x86_64)   echo "amd64" ;;
        aarch64)  echo "arm64" ;;
        armv7l)   echo "armv7" ;;
        *)
            echo -e "${red}Неподдерживаемая архитектура: $(uname -m)${plain}"
            exit 1
            ;;
    esac
}

# ─── Последний релиз из GitHub ────────────────────────────────────────────────

get_latest_release() {
    local repo=$1
    local url="https://api.github.com/repos/${repo}/releases/latest"
    curl -fsSL "$url" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
}

# ─── Установка amneziawg-go ───────────────────────────────────────────────────

install_awg_go() {
    echo -e "${yellow}Установка amneziawg-go...${plain}"
    local arch
    arch=$(detect_arch)
    local version
    version=$(get_latest_release "$AWG_GO_REPO")

    if [ -z "$version" ]; then
        echo -e "${red}Не удалось получить версию amneziawg-go${plain}"
        exit 1
    fi

    echo "Версия: $version, архитектура: $arch"

    # Бинарник называется amneziawg-go-linux-<arch> в releases
    local filename="amneziawg-go-linux-${arch}"
    local url="https://github.com/${AWG_GO_REPO}/releases/download/${version}/${filename}"

    echo "Загрузка: $url"
    curl -fsSL "$url" -o "${TMP_DIR}/amneziawg-go"
    chmod +x "${TMP_DIR}/amneziawg-go"
    mv "${TMP_DIR}/amneziawg-go" "${INSTALL_DIR}/amneziawg-go"
    echo -e "${green}amneziawg-go установлен в ${INSTALL_DIR}/amneziawg-go${plain}"
}

# ─── Установка awg-tools ──────────────────────────────────────────────────────

install_awg_tools() {
    echo -e "${yellow}Установка awg-tools...${plain}"

    # Сначала пробуем пакетный менеджер
    if command -v apt-get &>/dev/null; then
        # Пробуем из репозитория Amnezia если есть
        if apt-cache show amneziawg-tools &>/dev/null 2>&1; then
            apt-get install -y amneziawg-tools
            echo -e "${green}awg-tools установлены через apt${plain}"
            return
        fi
    fi

    # Fallback: собираем из исходников
    echo "Сборка awg из исходников..."
    if ! command -v make &>/dev/null; then
        apt-get install -y make gcc 2>/dev/null || yum install -y make gcc 2>/dev/null || true
    fi

    local version
    version=$(get_latest_release "$AWG_TOOLS_REPO")
    local src_url="https://github.com/${AWG_TOOLS_REPO}/archive/refs/tags/${version}.tar.gz"

    curl -fsSL "$src_url" -o "${TMP_DIR}/awg-tools.tar.gz"
    tar -xzf "${TMP_DIR}/awg-tools.tar.gz" -C "${TMP_DIR}"
    local src_dir
    src_dir=$(find "${TMP_DIR}" -maxdepth 1 -type d -name 'amneziawg-tools*' | head -1)

    if [ -n "$src_dir" ]; then
        cd "$src_dir"
        make -C src tools
        # Ищем бинарник awg в выводе make
        find . -name 'awg' -type f -exec cp {} "${INSTALL_DIR}/awg" \;
        chmod +x "${INSTALL_DIR}/awg"
        echo -e "${green}awg установлен в ${INSTALL_DIR}/awg${plain}"
        cd -
    else
        echo -e "${red}Не удалось найти директорию сборки awg-tools${plain}"
        exit 1
    fi
}

# ─── Проверка зависимостей ────────────────────────────────────────────────────

check_deps() {
    echo -e "${yellow}Проверка зависимостей...${plain}"
    local missing=()

    command -v curl    &>/dev/null || missing+=("curl")
    command -v ip      &>/dev/null || missing+=("iproute2")
    command -v iptables &>/dev/null || missing+=("iptables")

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${yellow}Установка отсутствующих пакетов: ${missing[*]}${plain}"
        if command -v apt-get &>/dev/null; then
            apt-get install -y "${missing[@]}" 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y "${missing[@]}" 2>/dev/null || true
        fi
    fi
}

# ─── Создание директорий ──────────────────────────────────────────────────────

setup_dirs() {
    mkdir -p /etc/amneziawg
    mkdir -p /var/run/amneziawg
    chmod 700 /etc/amneziawg
    echo -e "${green}Директории /etc/amneziawg и /var/run/amneziawg созданы${plain}"
}

# ─── Включение IP forwarding ─────────────────────────────────────────────────

enable_ip_forward() {
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-awg-forward.conf
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-awg-forward.conf
    sysctl -p /etc/sysctl.d/99-awg-forward.conf &>/dev/null || true
    echo -e "${green}IP forwarding включён${plain}"
}

# ─── Проверка установки ───────────────────────────────────────────────────────

verify_install() {
    echo -e "\n${yellow}Проверка установки:${plain}"
    if command -v amneziawg-go &>/dev/null; then
        echo -e "  ${green}✓ amneziawg-go: $(which amneziawg-go)${plain}"
    else
        echo -e "  ${red}✗ amneziawg-go не найден${plain}"
    fi

    if command -v awg &>/dev/null; then
        echo -e "  ${green}✓ awg: $(which awg)${plain}"
    else
        echo -e "  ${red}✗ awg не найден${plain}"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    echo -e "${green}========================================${plain}"
    echo -e "${green}  Установка AmneziaWG 2.0 для 3x-ui   ${plain}"
    echo -e "${green}========================================${plain}"

    check_deps
    install_awg_go
    install_awg_tools
    setup_dirs
    enable_ip_forward
    verify_install

    rm -rf "${TMP_DIR}"
    echo -e "\n${green}AmneziaWG 2.0 успешно установлен!${plain}"
    echo -e "${yellow}Теперь создай AmneziaWG inbound в панели 3x-ui.${plain}"
}

main "$@"
