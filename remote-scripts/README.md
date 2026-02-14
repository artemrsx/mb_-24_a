# Marzban VPN — Удалённые скрипты установки

Самодостаточные скрипты для установки панели Marzban и нод напрямую на VPS.
Не требуют локальной машины — запускаются одной командой через `curl`.

## Быстрый старт

### 1. Установка панели

SSH на VPS панели и выполнить:

```bash
sudo ADMIN_USER=admin ADMIN_PASS=mypass SERVER_COUNTRY=Finland \
  bash -c "$(curl -sL https://raw.githubusercontent.com/artemrsx/mb_-24_a/refs/heads/main/install-panel.sh)"
```

После установки скрипт выведет учётные данные и команду для установки ноды.

### 2. Установка ноды

SSH на VPS ноды и выполнить (подставить данные из вывода панельного скрипта):

```bash
sudo PANEL_URL=https://1.2.3.4:8000 ADMIN_USER=admin ADMIN_PASS=mypass NODE_NAME=Node-1 \
  bash -c "$(curl -sL https://raw.githubusercontent.com/artemrsx/mb_-24_a/refs/heads/main/install-node.sh)"
```

## Переменные окружения

### install-panel.sh

| Переменная | Обязательная | По умолчанию | Описание |
|---|---|---|---|
| `ADMIN_USER` | нет | `admin` | Логин администратора панели |
| `ADMIN_PASS` | нет | *генерируется* | Пароль администратора |
| `DB_PASSWORD` | нет | *генерируется* | Пароль MariaDB |
| `PANEL_PORT` | нет | `8000` | Порт дашборда |
| `SERVER_COUNTRY` | нет | `Server` | Страна сервера (отображается в клиентах) |
| `REALITY_DEST` | нет | `www.google.com:443` | Целевой сайт для маскировки трафика |
| `REALITY_SERVER_NAMES` | нет | `www.google.com` | SNI для Reality |

### install-node.sh

| Переменная | Обязательная | По умолчанию | Описание |
|---|---|---|---|
| `PANEL_URL` | **да** | — | URL панели (например `https://1.2.3.4:8000`) |
| `ADMIN_USER` | **да** | — | Логин администратора панели |
| `ADMIN_PASS` | **да** | — | Пароль администратора панели |
| `NODE_NAME` | нет | `Node-1` | Имя ноды в панели |

## Что делают скрипты

### install-panel.sh

1. Устанавливает Marzban через официальный скрипт (Docker + MariaDB)
2. Генерирует самоподписанный SSL-сертификат для HTTPS
3. Генерирует ключи x25519 для протокола Reality
4. Настраивает конфигурацию Xray (VLESS Reality на порту 443, VLESS WebSocket на порту 2095)
5. Запускает панель и проверяет работоспособность API
6. Создаёт тестового VPN-пользователя `test-user`
7. Сохраняет состояние в `/opt/marzban/deploy-state`

### install-node.sh

1. Устанавливает Docker CE (если не установлен)
2. Настраивает файрвол (UFW)
3. Получает SSL-сертификат от панели через API
4. Запускает контейнер ноды
5. Регистрирует ноду в панели

## Требования

- Ubuntu 22+ на VPS
- Root-доступ (sudo)
- `curl` и `openssl` (обычно предустановлены)
- Панель должна быть установлена до нод

## Проверка после установки

1. Дашборд: `https://<IP_ПАНЕЛИ>:8000/dashboard/` (принять предупреждение о сертификате)
2. Логин: использовать `ADMIN_USER` / `ADMIN_PASS`
3. Ноды: проверить статус в разделе "Настройки нод" дашборда
4. VPN: скопировать подписку `test-user` из дашборда в клиент (v2rayN, Streisand, Nekoray)

## Полезные команды на VPS

### Панель

```bash
marzban status       # Статус
marzban logs         # Логи
marzban restart      # Перезапуск
cat /opt/marzban/deploy-state  # Учётные данные
```

### Нода

```bash
cd /opt/marzban-node
docker compose ps       # Статус
docker compose logs     # Логи
docker compose restart  # Перезапуск
```
