#!/bin/bash
# Скрипт установки Adaptive Signature Filter
# Для Ubuntu/Debian систем

set -e

echo "=========================================="
echo "Adaptive Signature Filter - Установка"
echo "=========================================="

# Проверка root
if [ "$EUID" -ne 0 ]; then 
    echo "Запустите скрипт с правами root (sudo)"
    exit 1
fi

# Обновление пакетов
echo "[1/6] Обновление списка пакетов..."
apt-get update

# Установка системных зависимостей
echo "[2/6] Установка системных зависимостей..."
apt-get install -y \
    golang \
    libpcap-dev \
    python3 \
    python3-pip \
    sqlite3 \
    curl \
    make \
    gcc

# Установка Python зависимостей
echo "[3/6] Установка Python зависимостей..."
pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests

# Проверка версии Go
echo "[4/6] Проверка версии Go..."
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "Go версия: $GO_VERSION"

# Сборка Go-движка
echo "[5/6] Сборка Go-движка..."
cd go-engine
go mod download
CGO_ENABLED=1 go build -o ../build/signature-engine .
cd ..

# Инициализация базы данных
echo "[6/6] Инициализация базы данных..."
python3 database/init_db.py -d signatures.db --show

# Создание директорий для логов
mkdir -p /var/log/signature-engine

# Создание systemd сервиса (опционально)
cat > /etc/systemd/system/signature-engine.service << EOF
[Unit]
Description=Adaptive Signature Filter Engine
After=network.target

[Service]
Type=simple
ExecStart=$(pwd)/build/signature-engine -config $(pwd)/config/config.json -interface eth0
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "=========================================="
echo "Установка завершена!"
echo "=========================================="
echo ""
echo "Использование:"
echo "  Ручной запуск:   sudo ./build/signature-engine -interface eth0"
echo "  Через systemd:   sudo systemctl start signature-engine"
echo "  Мониторинг:      make run-monitor"
echo "  Тестирование:    make test"
echo ""
echo "API доступен на: http://localhost:8080"
echo ""
