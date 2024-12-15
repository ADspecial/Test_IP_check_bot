#!/bin/bash

# Папка для хранения сертификатов и ключей
CERT_DIR="./certs"
mkdir -p $CERT_DIR

# Создаем корневой (CA) ключ и сертификат
openssl genpkey -algorithm RSA -out $CERT_DIR/rootCA.key -pkeyopt rsa_keygen_bits:4096
openssl req -x509 -new -nodes -key $CERT_DIR/rootCA.key -sha256 -days 3650 -out $CERT_DIR/rootCA.crt -subj "/C=RU/ST=State/L=City/O=Company/OU=IT Department/CN=RootCA"

# Создаем серверный ключ
openssl genpkey -algorithm RSA -out $CERT_DIR/server.key -pkeyopt rsa_keygen_bits:2048

# Создаем запрос на подписание для серверного сертификата
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr -subj "/C=RU/ST=State/L=City/O=Company/OU=IT Department/CN=172.18.0.4"

# Создаем конфигурационный файл для расширений x509, включая IP-адрес сервера
cat > $CERT_DIR/server_cert_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:172.18.0.4
EOF

# Подписываем серверный сертификат корневым сертификатом
openssl x509 -req -in $CERT_DIR/server.csr -CA $CERT_DIR/rootCA.crt -CAkey $CERT_DIR/rootCA.key -CAcreateserial \
-out $CERT_DIR/server.crt -days 365 -sha256 -extfile $CERT_DIR/server_cert_ext.cnf

# Устанавливаем права доступа на серверные ключи
chmod 644 $CERT_DIR/rootCA.crt
chmod 644 $CERT_DIR/server.crt
chmod 600 $CERT_DIR/server.key

# Генерация клиентского ключа
openssl genpkey -algorithm RSA -out $CERT_DIR/client.key -pkeyopt rsa_keygen_bits:2048

# Создание запроса на подписание для клиентского сертификата
openssl req -new -key $CERT_DIR/client.key -out $CERT_DIR/client.csr -subj "/C=RU/ST=State/L=City/O=Company/OU=IT Department/CN=Client"

# Подпись клиентского сертификата корневым сертификатом
openssl x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/rootCA.crt -CAkey $CERT_DIR/rootCA.key -CAcreateserial \
-out $CERT_DIR/client.crt -days 365 -sha256

# Устанавливаем права доступа на клиентские ключи
chmod 644 $CERT_DIR/client.crt
chmod 600 $CERT_DIR/client.key

# Очистка промежуточных файлов
rm $CERT_DIR/server.csr $CERT_DIR/client.csr $CERT_DIR/server_cert_ext.cnf $CERT_DIR/rootCA.srl

echo "Сертификаты и ключи успешно созданы в папке $CERT_DIR."
