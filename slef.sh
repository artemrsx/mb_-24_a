EMAIL=$1
DOMAIN=$2
USER_NAME=$3
PASSWORD=$4
TELEGRAM_ID=$5

marzban uninstall

systemctl stop nginx
apt install -y nginx
mkdir -p /var/www/html
systemctl start nginx

# certs
systemctl stop nginx
curl https://get.acme.sh | sh -s email="$EMAIL"

mkdir -p /var/lib/marzban/certs
~/.acme.sh/acme.sh \
  --issue --force -w /var/www/html -d "$DOMAIN" \
  --fullchain-file "/var/lib/marzban/certs/$DOMAIN.cer" \
  --key-file "/var/lib/marzban/certs/$DOMAIN.cer.key"
systemctl start nginx
cat /var/lib/marzban/certs/$DOMAIN.cer

# Проверка наличия файлов сертификата
if [ ! -f "/var/lib/marzban/certs/$DOMAIN.cer" ] || [ ! -f "/var/lib/marzban/certs/$DOMAIN.cer.key" ]; then
    echo "ОШИБКА: Файлы сертификата не были созданы."
    exit 1
fi

# Marzban
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

# nginx
cat << EOF > /etc/nginx/sites-available/default
server {
        listen 80;
        server_name $DOMAIN;
        return 301 https://\$http_host\$request_uri;
       }


server {
        listen 127.0.0.1:8080;
        server_name $DOMAIN;
        root /var/www/html/;
        index index.html;
        add_header Strict-Transport-Security "max-age=63072000" always;
}
EOF
mv /var/www/html/index.nginx-debian.html /var/www/html/index.html
systemctl restart nginx

# Вывести конфигурацию
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
      "tag": "VLESS TCP TLS",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 8080
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": "http/1.1",
          "certificates": [
            {
              "certificateFile": "/var/lib/marzban/certs/$DOMAIN.cer",
              "keyFile": "/var/lib/marzban/certs/$DOMAIN.cer.key"
            }
          ],
          "minVersion": "1.2",
          "cipherSuites": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
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

marzban restart
