#!/usr/bin/env bash
# install-panel.sh — Установка панели Marzban на VPS (самодостаточный скрипт)
#
# Запуск на VPS:
#   sudo ADMIN_USER=admin ADMIN_PASS=mypass SERVER_COUNTRY=Finland \
#     bash -c "$(curl -sL https://raw.githubusercontent.com/artemrsx/mb_-24_a/refs/heads/main/install-panel.sh)"
#
# Переменные окружения:
#   ADMIN_USER         — логин администратора (по умолчанию: admin)
#   ADMIN_PASS         — пароль администратора (генерируется, если пустой)
#   DB_PASSWORD        — пароль MariaDB (генерируется, если пустой)
#   PANEL_PORT         — порт дашборда (по умолчанию: 8000)
#   PANEL_DOMAIN       — домен панели (опционально; если задан — SSL через Let's Encrypt)
#   SERVER_COUNTRY     — страна сервера для отображения в клиентах (по умолчанию: Server)
#   REALITY_DEST       — целевой сайт для маскировки (по умолчанию: www.google.com:443)
#   REALITY_SERVER_NAMES — SNI для Reality (по умолчанию: www.google.com)

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# ВСТРОЕННЫЕ УТИЛИТЫ
# ══════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()    { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }
die() { log_error "$@"; exit 1; }

gen_password() {
    local length="${1:-24}"
    openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c "$length"
}

# Обновляет или добавляет переменную в .env файле (локально на VPS)
update_env() {
    local env_file="$1" key="$2" value="$3"
    if grep -q "^${key}=" "$env_file" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$env_file"
    else
        echo "${key}=${value}" >> "$env_file"
    fi
}

# Ожидает доступности API панели
wait_for_api() {
    local url="$1"
    local max_attempts="${2:-60}"
    local attempt=0

    log_info "Ожидание API: ${url} ..."
    while [ $attempt -lt $max_attempts ]; do
        local http_code
        http_code=$(curl -sk -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || echo "000")
        if [ "$http_code" = "200" ] || [ "$http_code" = "405" ] || [ "$http_code" = "422" ]; then
            log_success "API доступен (HTTP ${http_code})"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
    die "API не стал доступен за $((max_attempts * 5)) секунд"
}

# Получает токен авторизации от API панели
api_get_token() {
    local panel_url="$1" username="$2" password="$3"
    local response
    response=$(curl -skf -X POST "${panel_url}/api/admin/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${username}&password=${password}" 2>/dev/null) || return 1
    echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null
}

# Выполняет авторизованный запрос к API панели
api_call() {
    local method="$1" url="$2" token="$3"
    shift 3
    curl -skf -X "$method" "$url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        "$@" 2>/dev/null
}

# ══════════════════════════════════════════════════════════════════════════════
# КОНФИГУРАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-}"
DB_PASSWORD="${DB_PASSWORD:-}"
PANEL_PORT="${PANEL_PORT:-8000}"
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
SERVER_COUNTRY="${SERVER_COUNTRY:-Server}"
REALITY_DEST="${REALITY_DEST:-www.google.com:443}"
REALITY_SERVER_NAMES="${REALITY_SERVER_NAMES:-www.google.com}"

MARZBAN_SCRIPT_URL="https://github.com/Gozargah/Marzban-scripts/raw/master/marzban.sh"
STATE_FILE="/opt/marzban/deploy-state"

# ══════════════════════════════════════════════════════════════════════════════
# ВСТРОЕННЫЙ ШАБЛОН XRAY CONFIG
# ══════════════════════════════════════════════════════════════════════════════

XRAY_CONFIG_TEMPLATE='{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "VLESS_REALITY",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "tcpSettings": {},
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "{{REALITY_DEST}}",
          "xver": 0,
          "serverNames": [
            "{{REALITY_SERVER_NAME}}"
          ],
          "privateKey": "{{REALITY_PRIVATE_KEY}}",
          "shortIds": [
            "",
            "0123456789abcdef"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    },
    {
      "tag": "VLESS_WS",
      "listen": "0.0.0.0",
      "port": 2095,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless-ws"
        },
        "security": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom"
    },
    {
      "tag": "BLACKHOLE",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "BLACKHOLE",
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "DIRECT",
        "network": "tcp,udp"
      }
    ]
  }
}'

# ══════════════════════════════════════════════════════════════════════════════
# НАЧАЛО УСТАНОВКИ
# ══════════════════════════════════════════════════════════════════════════════

log_step "Установка панели Marzban"

# Проверяем, что скрипт запущен от root
[ "$(id -u)" -eq 0 ] || die "Скрипт должен быть запущен от root (sudo)"

# Проверяем наличие необходимых утилит
for cmd in curl openssl; do
    command -v "$cmd" >/dev/null 2>&1 || die "Команда не найдена: $cmd"
done

# Генерируем пароли, если не заданы
if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS=$(gen_password 16)
    log_info "Сгенерирован пароль администратора"
fi
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(gen_password 24)
    log_info "Сгенерирован пароль базы данных"
fi

# Определяем публичный IP сервера
log_info "Определяем публичный IP сервера..."
PANEL_IP=$(curl -s4 --max-time 10 ifconfig.me 2>/dev/null) || \
PANEL_IP=$(curl -s4 --max-time 10 api.ipify.org 2>/dev/null) || \
PANEL_IP=$(hostname -I | awk '{print $1}')

[ -z "$PANEL_IP" ] && die "Не удалось определить IP-адрес сервера"
log_success "IP сервера: ${PANEL_IP}"

# Если задан домен — используем его для URL, иначе IP
PANEL_HOST="${PANEL_DOMAIN:-${PANEL_IP}}"
PANEL_URL="https://${PANEL_HOST}:${PANEL_PORT}"

# ── Шаг 1: Установка Marzban через официальный скрипт ─────────────────────
log_step "Шаг 1/4: Установка Marzban через официальный скрипт"

log_info "Скачиваем официальный установочный скрипт..."
curl -sL "${MARZBAN_SCRIPT_URL}" -o /tmp/marzban.sh && chmod +x /tmp/marzban.sh

log_info "Запускаем установку (это может занять несколько минут)..."
echo "${DB_PASSWORD}" | timeout 300 bash /tmp/marzban.sh install --database mariadb || true

# Проверяем, что установка прошла успешно
test -f /opt/marzban/docker-compose.yml \
    || die "Установка Marzban не удалась — файл docker-compose.yml не найден"
command -v marzban >/dev/null \
    || die "Установка Marzban не удалась — CLI-команда marzban не найдена"
log_success "Marzban установлен через официальный скрипт"

# ── Шаг 2: Генерация ключей и сертификатов ─────────────────────────────────
log_step "Шаг 2/4: Генерация ключей и сертификатов"

marzban down 2>/dev/null || (cd /opt/marzban && docker compose down 2>/dev/null) || true

# SSL-сертификат
SSL_CERT_FILE=""
SSL_KEY_FILE=""
SSL_CA_TYPE=""

if [ -n "$PANEL_DOMAIN" ]; then
    # Домен задан — используем Let's Encrypt через certbot
    log_info "Установка certbot для Let's Encrypt..."
    apt-get update -qq && apt-get install -y -qq certbot >/dev/null 2>&1

    log_info "Получение SSL-сертификата Let's Encrypt для ${PANEL_DOMAIN}..."
    certbot certonly --standalone -d "${PANEL_DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email \
        || die "Не удалось получить сертификат Let's Encrypt. Проверьте, что домен ${PANEL_DOMAIN} указывает на IP ${PANEL_IP} и порт 80 открыт."

    SSL_CERT_FILE="/etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem"
    SSL_KEY_FILE="/etc/letsencrypt/live/${PANEL_DOMAIN}/privkey.pem"

    # Автообновление сертификата с перезапуском Marzban
    echo '0 3 * * * root certbot renew --quiet --deploy-hook "cd /opt/marzban && docker compose restart"' > /etc/cron.d/certbot-marzban
    log_success "SSL-сертификат Let's Encrypt получен для ${PANEL_DOMAIN}"
else
    # Домен не задан — генерируем самоподписанный сертификат
    log_info "Генерация самоподписанного SSL-сертификата..."
    mkdir -p /var/lib/marzban/certs
    openssl req -x509 -newkey rsa:2048 \
        -keyout /var/lib/marzban/certs/key.pem \
        -out /var/lib/marzban/certs/cert.pem \
        -days 3650 -nodes -subj "/CN=${PANEL_IP}" 2>/dev/null

    SSL_CERT_FILE="/var/lib/marzban/certs/cert.pem"
    SSL_KEY_FILE="/var/lib/marzban/certs/key.pem"
    SSL_CA_TYPE="private"
    log_success "Самоподписанный SSL-сертификат создан"
fi

# Генерируем ключи x25519 для протокола Reality
log_info "Генерация ключей Reality x25519..."
keys_output=$(docker run --rm gozargah/marzban:latest xray x25519 2>/dev/null) \
    || die "Не удалось сгенерировать ключи x25519"

private_key=$(echo "$keys_output" | grep "Private" | awk '{print $NF}')
public_key=$(echo "$keys_output" | grep "Public" | awk '{print $NF}')

[ -z "$private_key" ] && die "Не удалось получить приватный ключ x25519"
log_success "Reality-ключи сгенерированы (публичный: ${public_key})"

# ── Шаг 3: Настройка конфигурации ──────────────────────────────────────────
log_step "Шаг 3/4: Настройка конфигурации панели"

# Подставляем реальные ключи в шаблон Xray
xray_config="$XRAY_CONFIG_TEMPLATE"
xray_config=$(echo "$xray_config" | sed "s|{{REALITY_PRIVATE_KEY}}|${private_key}|g")
xray_config=$(echo "$xray_config" | sed "s|{{REALITY_DEST}}|${REALITY_DEST}|g")
xray_config=$(echo "$xray_config" | sed "s|{{REALITY_SERVER_NAME}}|${REALITY_SERVER_NAMES}|g")

echo "$xray_config" > /var/lib/marzban/xray_config.json
log_success "Конфигурация Xray записана"

# Настраиваем .env
log_info "Настройка переменных окружения панели..."
ENV_FILE="/opt/marzban/.env"

update_env "$ENV_FILE" "UVICORN_HOST" "0.0.0.0"
update_env "$ENV_FILE" "UVICORN_PORT" "${PANEL_PORT}"
update_env "$ENV_FILE" "UVICORN_SSL_CERTFILE" "${SSL_CERT_FILE}"
update_env "$ENV_FILE" "UVICORN_SSL_KEYFILE" "${SSL_KEY_FILE}"
if [ -n "$SSL_CA_TYPE" ]; then
    update_env "$ENV_FILE" "UVICORN_SSL_CA_TYPE" "${SSL_CA_TYPE}"
else
    # Удаляем CA_TYPE для Let's Encrypt (настоящий сертификат не требует)
    sed -i '/^UVICORN_SSL_CA_TYPE=/d' "$ENV_FILE" 2>/dev/null || true
fi
update_env "$ENV_FILE" "SUDO_USERNAME" "${ADMIN_USER}"
update_env "$ENV_FILE" "SUDO_PASSWORD" "${ADMIN_PASS}"
update_env "$ENV_FILE" "XRAY_JSON" "/var/lib/marzban/xray_config.json"
update_env "$ENV_FILE" "DOCS" "true"
update_env "$ENV_FILE" "XRAY_SUBSCRIPTION_URL_PREFIX" "${PANEL_URL}"

log_success "Переменные окружения настроены"

# ── Шаг 4: Запуск панели и проверка ─────────────────────────────────────────
log_step "Шаг 4/4: Запуск панели и проверка"

log_info "Запускаем Marzban..."
marzban up -n 2>/dev/null || (cd /opt/marzban && docker compose up -d)

# Ждём, пока API станет доступен
wait_for_api "${PANEL_URL}/api/admin/token" 60

# Проверяем авторизацию
token=$(api_get_token "$PANEL_URL" "$ADMIN_USER" "$ADMIN_PASS") \
    || die "Не удалось получить токен авторизации. Проверьте учётные данные."
log_success "API панели работает, авторизация подтверждена"

# Создаём тестового VPN-пользователя
log_info "Создаём тестового VPN-пользователя..."
test_user_payload='{
    "username": "test-user",
    "status": "active",
    "proxies": {
        "vless": {}
    },
    "inbounds": {
        "vless": ["VLESS_REALITY", "VLESS_WS"]
    },
    "data_limit": 0,
    "expire": 0,
    "note": "Тестовый пользователь, созданный скриптом деплоя"
}'

user_response=""
user_response=$(api_call POST "${PANEL_URL}/api/user" "$token" -d "$test_user_payload") || {
    log_warn "Не удалось создать тестового пользователя (возможно, он уже существует)"
    user_response=""
}

test_sub_url=""
test_links=""
if [ -n "$user_response" ]; then
    test_sub_url=$(echo "$user_response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('subscription_url',''))" 2>/dev/null) || true
    test_links=$(echo "$user_response" | python3 -c "
import sys,json
links = json.load(sys.stdin).get('links', [])
for l in links: print(l)
" 2>/dev/null) || true
    log_success "Тестовый пользователь 'test-user' создан"

    # Устанавливаем flow для VLESS Reality
    log_info "Настройка flow для VLESS Reality..."
    api_call PUT "${PANEL_URL}/api/user/test-user" "$token" -d '{
        "proxies": {
            "vless": {
                "flow": "xtls-rprx-vision"
            }
        }
    }' >/dev/null 2>&1 && log_success "Flow настроен для test-user" || log_warn "Не удалось установить flow"
fi

# Настраиваем хосты
log_info "Настройка хостов..."
host_payload=$(cat <<EOJSON
{
    "VLESS_REALITY": [
        {
            "remark": "${SERVER_COUNTRY}",
            "address": "${PANEL_HOST}",
            "port": null,
            "sni": null,
            "host": null,
            "security": "inbound_default",
            "alpn": "",
            "fingerprint": "",
            "allowinsecure": null,
            "is_disabled": false,
            "mux_enable": false,
            "fragment_setting": null,
            "noise_setting": null,
            "random_user_agent": false,
            "use_sni_as_host": false
        }
    ],
    "VLESS_WS": [
        {
            "remark": "${SERVER_COUNTRY}",
            "address": "${PANEL_HOST}",
            "port": null,
            "sni": null,
            "host": null,
            "security": "inbound_default",
            "alpn": "",
            "fingerprint": "",
            "allowinsecure": null,
            "is_disabled": false,
            "mux_enable": false,
            "fragment_setting": null,
            "noise_setting": null,
            "random_user_agent": false,
            "use_sni_as_host": false
        }
    ]
}
EOJSON
)
host_response=""
host_response=$(api_call PUT "${PANEL_URL}/api/hosts" "$token" -d "$host_payload") || {
    log_warn "Не удалось настроить хосты (возможно, они уже настроены)"
}
if [ -n "$host_response" ]; then
    log_success "Хосты настроены для ${SERVER_COUNTRY}"
fi

# ── Сохраняем состояние деплоя ──────────────────────────────────────────────
mkdir -p "$(dirname "$STATE_FILE")"
cat > "$STATE_FILE" <<EOF
# Состояние деплоя Marzban — создано автоматически, не редактировать вручную
PANEL_IP=${PANEL_IP}
PANEL_DOMAIN=${PANEL_DOMAIN}
PANEL_PORT=${PANEL_PORT}
PANEL_URL=${PANEL_URL}
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
REALITY_PUBLIC_KEY=${public_key}
TEST_SUB_URL=${test_sub_url}
DEPLOYED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
chmod 600 "$STATE_FILE"

# ── Итоговая информация ──────────────────────────────────────────────────────
echo ""
log_step "Установка панели завершена"
echo ""
echo -e "  Дашборд:        ${GREEN}${PANEL_URL}/dashboard/${NC}"
echo -e "  Администратор:  ${CYAN}${ADMIN_USER}${NC}"
echo -e "  Пароль:         ${CYAN}${ADMIN_PASS}${NC}"
echo -e "  Reality PubKey: ${CYAN}${public_key}${NC}"
echo ""
if [ -n "$test_sub_url" ]; then
    echo -e "  ${CYAN}Тестовый VPN-пользователь: test-user${NC}"
    echo -e "  Подписка: ${GREEN}${test_sub_url}${NC}"
    if [ -n "$test_links" ]; then
        echo ""
        echo -e "  ${CYAN}Ссылки для подключения:${NC}"
        echo "$test_links" | while IFS= read -r link; do
            echo -e "    ${link}"
        done
    fi
    echo ""
fi
echo -e "  ${CYAN}Состояние сохранено: ${STATE_FILE}${NC}"
echo ""
echo -e "  ${YELLOW}Для установки ноды выполните на VPS ноды:${NC}"
echo -e "  ${GREEN}sudo PANEL_URL=${PANEL_URL} ADMIN_USER=${ADMIN_USER} ADMIN_PASS=${ADMIN_PASS} NODE_NAME=Node-1 \\"
echo -e "    bash -c \"\\\$(curl -sL https://raw.githubusercontent.com/artemrsx/mb_-24_a/refs/heads/main/install-node.sh)\"${NC}"
echo ""
