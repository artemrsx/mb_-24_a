#!/usr/bin/env bash
# install-node.sh — Установка ноды Marzban на VPS (самодостаточный скрипт)
#
# Запуск на VPS ноды:
#   sudo PANEL_URL=https://1.2.3.4:8000 ADMIN_USER=admin ADMIN_PASS=mypass NODE_NAME=Node-1 \
#     bash -c "$(curl -sL https://raw.githubusercontent.com/artemrsx/mb_-24_a/refs/heads/main/install-node.sh)"
#
# Переменные окружения (обязательные):
#   PANEL_URL    — URL панели Marzban (например: https://1.2.3.4:8000)
#   ADMIN_USER   — логин администратора панели
#   ADMIN_PASS   — пароль администратора панели
#
# Переменные окружения (опциональные):
#   NODE_NAME    — имя ноды для отображения в панели (по умолчанию: Node-1)

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

PANEL_URL="${PANEL_URL:-}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PASS="${ADMIN_PASS:-}"
NODE_NAME="${NODE_NAME:-Node-1}"

NODE_DIR="/opt/marzban-node"
NODE_DATA="/var/lib/marzban-node"

# ══════════════════════════════════════════════════════════════════════════════
# ВСТРОЕННЫЙ DOCKER-COMPOSE ДЛЯ НОДЫ
# ══════════════════════════════════════════════════════════════════════════════

DOCKER_COMPOSE_CONTENT='# Docker Compose для ноды Marzban
services:
  marzban-node:
    image: gozargah/marzban-node:latest
    restart: always
    network_mode: host
    environment:
      SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/ssl_client_cert.pem"
      SERVICE_PROTOCOL: rest
    volumes:
      - /var/lib/marzban-node:/var/lib/marzban-node
'

# ══════════════════════════════════════════════════════════════════════════════
# НАЧАЛО УСТАНОВКИ
# ══════════════════════════════════════════════════════════════════════════════

log_step "Установка ноды Marzban: ${NODE_NAME}"

# Проверяем, что скрипт запущен от root
[ "$(id -u)" -eq 0 ] || die "Скрипт должен быть запущен от root (sudo)"

# Проверяем обязательные переменные
[ -z "$PANEL_URL" ] && die "PANEL_URL не задан. Пример: PANEL_URL=https://1.2.3.4:8000"
[ -z "$ADMIN_USER" ] && die "ADMIN_USER не задан"
[ -z "$ADMIN_PASS" ] && die "ADMIN_PASS не задан"

# Проверяем наличие curl
command -v curl >/dev/null 2>&1 || die "Команда не найдена: curl"

# Определяем публичный IP ноды
log_info "Определяем публичный IP ноды..."
NODE_IP=$(curl -s4 --max-time 10 ifconfig.me 2>/dev/null) || \
NODE_IP=$(curl -s4 --max-time 10 api.ipify.org 2>/dev/null) || \
NODE_IP=$(hostname -I | awk '{print $1}')

[ -z "$NODE_IP" ] && die "Не удалось определить IP-адрес ноды"
log_success "IP ноды: ${NODE_IP}"

# ── Шаг 1: Установка Docker ─────────────────────────────────────────────────
log_step "Шаг 1/4: Установка Docker"

export DEBIAN_FRONTEND=noninteractive

if command -v docker &>/dev/null && docker info &>/dev/null; then
    log_success "Docker уже установлен и запущен"
    docker --version
else
    log_info "Устанавливаем зависимости..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release >/dev/null

    log_info "Добавляем репозиторий Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

    log_info "Устанавливаем Docker CE..."
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null

    systemctl enable docker --now
    log_success "Docker установлен"
    docker --version
fi

# Настраиваем файрвол (UFW), если он активен
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    log_info "Настраиваем правила файрвола UFW..."
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 2095/tcp >/dev/null 2>&1 || true
    ufw allow 62050/tcp >/dev/null 2>&1 || true
    ufw allow 62051/tcp >/dev/null 2>&1 || true
    log_success "Правила UFW настроены"
fi

# ── Шаг 2: Получение сертификата от панели ───────────────────────────────────
log_step "Шаг 2/4: Получение сертификата ноды от панели"

# Авторизуемся в API панели
token=$(api_get_token "$PANEL_URL" "$ADMIN_USER" "$ADMIN_PASS") \
    || die "Не удалось авторизоваться в API панели. Проверьте PANEL_URL, ADMIN_USER, ADMIN_PASS."

# Запрашиваем сертификат
cert_response=$(api_call GET "${PANEL_URL}/api/node/settings" "$token") \
    || die "Не удалось получить настройки ноды из API панели"

certificate=$(echo "$cert_response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('certificate',''))" 2>/dev/null) \
    || die "Не удалось извлечь сертификат из ответа API"

[ -z "$certificate" ] && die "Получен пустой сертификат от панели"
log_success "Сертификат ноды получен"

# ── Шаг 3: Загрузка конфигурации ноды ────────────────────────────────────────
log_step "Шаг 3/4: Настройка конфигурации ноды"

mkdir -p "$NODE_DIR" "$NODE_DATA"

# Записываем docker-compose.yml
echo "$DOCKER_COMPOSE_CONTENT" > "${NODE_DIR}/docker-compose.yml"
log_success "docker-compose.yml записан"

# Записываем SSL-сертификат
echo "$certificate" > "${NODE_DATA}/ssl_client_cert.pem"
log_success "SSL-сертификат записан"

# ── Шаг 4: Запуск ноды и регистрация в панели ────────────────────────────────
log_step "Шаг 4/4: Запуск ноды и регистрация в панели"

cd "$NODE_DIR"

# Останавливаем предыдущие контейнеры (если есть)
if docker compose ps -q 2>/dev/null | grep -q .; then
    log_info "Останавливаем предыдущий контейнер ноды..."
    docker compose down --timeout 10
fi

# Скачиваем свежий образ
log_info "Скачиваем образ Marzban Node..."
docker compose pull -q

# Запускаем контейнер
log_info "Запускаем ноду Marzban..."
docker compose up -d

# Ждём запуска контейнера
log_info "Ожидание запуска ноды..."
attempt=0
max_attempts=30
while [ $attempt -lt $max_attempts ]; do
    if docker compose ps --format json 2>/dev/null | grep -q '"running"'; then
        log_success "Нода Marzban запущена"
        break
    fi
    if docker compose ps 2>/dev/null | grep -q "Up"; then
        log_success "Нода Marzban запущена"
        break
    fi
    attempt=$((attempt + 1))
    sleep 3
done
if [ $attempt -eq $max_attempts ]; then
    log_error "Нода Marzban не запустилась"
    docker compose logs marzban-node
    die "Контейнер ноды не запустился за 90 секунд"
fi

# Регистрируем ноду в панели
log_info "Регистрация ноды в панели..."
node_payload=$(cat <<EOJSON
{
    "name": "${NODE_NAME}",
    "address": "${NODE_IP}",
    "port": 62050,
    "api_port": 62051,
    "usage_coefficient": 1
}
EOJSON
)

register_response=""
register_response=$(api_call POST "${PANEL_URL}/api/node" "$token" -d "$node_payload") || {
    log_warn "Не удалось зарегистрировать ноду через API. Добавьте её вручную в панели:"
    log_warn "Перейдите: ${PANEL_URL}/dashboard/ → Настройки нод → Добавить ноду"
    log_warn "  Имя: ${NODE_NAME}"
    log_warn "  Адрес: ${NODE_IP}"
    log_warn "  Порт: 62050, API порт: 62051"
}

if [ -n "$register_response" ]; then
    log_success "Нода зарегистрирована в панели"
fi

# Ждём подключения ноды к панели
sleep 5
nodes_list=$(api_call GET "${PANEL_URL}/api/nodes" "$token" 2>/dev/null) || true

# ── Итоговая информация ──────────────────────────────────────────────────────
echo ""
log_step "Установка ноды завершена"
echo ""
echo -e "  Имя ноды:    ${CYAN}${NODE_NAME}${NC}"
echo -e "  IP ноды:     ${CYAN}${NODE_IP}${NC}"
echo -e "  REST-порт:   ${CYAN}62050${NC}"
echo -e "  Xray API:    ${CYAN}62051${NC}"
echo -e "  Панель:      ${CYAN}${PANEL_URL}/dashboard/${NC}"
echo ""
echo -e "  ${YELLOW}Проверьте подключение ноды в дашборде панели${NC}"
echo ""
