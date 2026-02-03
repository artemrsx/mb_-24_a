#!/bin/bash

NODE_NAME=$1
CERTIFICATE=$2

# 1. Проверка входных данных (чтобы не затереть конфиги пустыми данными)
if [ -z "$NODE_NAME" ] || [ -z "$CERTIFICATE" ]; then
  echo "Usage: $0 <node_name> '<certificate_content>'"
  exit 1
fi

# 2. Обновляем сервер и софт
apt-get update && apt-get upgrade -y
apt-get install curl socat git -y

# 3. Быстрая установка node
sudo bash -c "$(curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban-node.sh)" @ install --name "$NODE_NAME"

# 4. Создаем файл для сертификата
sudo mkdir -p /var/lib/marzban-node/

# 5. Записываем сертификат
sudo tee /var/lib/marzban-node/ssl_client_cert.pem <<EOF > /dev/null
$CERTIFICATE
EOF

# 6. Прастим путь в docker-compose.yml автоматически
# Скрипт установки может создать файл с дефолтными путями, лучше их перепроверить/заменить
sed -i 's|SSL_CLIENT_CERT_FILE:.*|SSL_CLIENT_CERT_FILE: "/var/lib/marzban-node/ssl_client_cert.pem"|' /opt/marzban-node/docker-compose.yml

# 7. Перезапускаем ноду
cd /opt/marzban-node && docker compose down && docker compose up -d
