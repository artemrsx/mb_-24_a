#!/bin/bash

NODE_NAME=$1
CERTIFICATE=$2

# Проверка входных данных (чтобы не затереть конфиги пустыми данными)
if [ -z "$NODE_NAME" ] || [ -z "$CERTIFICATE" ]; then
  echo "Usage: $0 <node_name> '<certificate_content>'"
  exit 1
fi

# Обновляем сервер и софт
apt-get update && apt-get upgrade -y
apt-get install curl socat git -y

# Быстрая установка node
# 1. Сертификат
# 2. Enter (завершить ввод сертификата)
# 3. y (согласиться на REST)
# 4. Enter (согласиться на service port по умолчанию 62050)
# 5. Enter (согласиться на xray port по умолчанию 62051)
printf "${CERTIFICATE}\n\ny\n\n\n" | sudo bash -c "$(curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban-node.sh)" @ install --name "$NODE_NAME"

# Создаем файл для сертификата
sudo mkdir -p /var/lib/marzban-node/

# Записываем сертификат
sudo tee /var/lib/marzban-node/ssl_client_cert.pem <<EOF > /dev/null
$CERTIFICATE
EOF

# Прастим путь в docker-compose.yml автоматически
# Скрипт установки может создать файл с дефолтными путями, лучше их перепроверить/заменить
sed -i "s|SSL_CLIENT_CERT_FILE:.*|SSL_CLIENT_CERT_FILE: \"/var/lib/marzban-node/ssl_client_cert.pem\"|" /opt/$NODE_NAME/docker-compose.yml

# На всякий случай открываем нужные порты (по дефолту они и так отрыты)
ufw allow 62050/tcp
ufw allow 62051/tcp
ufw allow 443/tcp

# Перезапускаем ноду
cd /opt/$NODE_NAME && docker compose down && docker compose up -d

echo "Нода $NODE_NAME успешно настроена и запущена!"
