# Установка нужных пакетов
apt update
apt install -y curl
apt install -y socat

# Скачиваем утилиту, которая автоматически создаст нам сертификат после запуска
curl https://get.acme.sh | sh -s email="$EMAIL"

# Запускаем утилиту, которая создаст сертификат
mkdir -p /var/lib/marzban/certs
~/.acme.sh/acme.sh \
  --issue --force --standalone -d "$DOMAIN" \
  --fullchain-file "/var/lib/marzban/certs/$DOMAIN.cer" \
  --key-file "/var/lib/marzban/certs/$DOMAIN.cer.key"

# Устанавливаем Marzban
sudo bash -c "$(curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban.sh)" @ install

# Меняем Marzban конфиг
echo "" >> /opt/marzban/.env
echo "UVICORN_SSL_CERTFILE = \"/var/lib/marzban/certs/$DOMAIN.cer\"" >> /opt/marzban/.env
echo "UVICORN_SSL_KEYFILE = \"/var/lib/marzban/certs/$DOMAIN.cer.key\"" >> /opt/marzban/.env
echo "XRAY_SUBSCRIPTION_URL_PREFIX = \"https://$DOMAIN\"" >> /opt/marzban/.env

# Перезапускаем Marzban и создаем admin пользователя
marzban restart
marzban cli admin create --sudo \
--username "$USER_NAME" \
--password "$PASSWORD" \
--telegram-id "$TELEGRAM_ID" \
--discord-webhook ''

# Получить private & public keys и вывести конфигурацию
XRAY_OUTPUT=$(docker exec marzban-marzban-1 xray x25519)
PRIV_KEY=$(echo "$XRAY_OUTPUT" | grep "Private key:" | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 8)

echo -e "\n--- Итоговый конфиг ---"
cat <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "routing": {
    "rules": [
      {
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "BLOCK",
        "type": "field"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "VLESS TCP REALITY",
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
          "dest": "github.com:443",
          "xver": 0,
          "serverNames": [
            "github.com"
          ],
          "privateKey": "$PRIV_KEY",
          "shortIds": [
            "$SHORT_ID"
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
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "DIRECT"
    },
    {
      "protocol": "blackhole",
      "tag": "BLOCK"
    }
  ]
}
EOF
