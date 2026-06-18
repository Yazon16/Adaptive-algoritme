# Adaptive Signature Filter

Высокопроизводительный движок сигнатурного анализа для адаптивной фильтрации сетевого трафика в корпоративных вычислительных сетях.

## Архитектура

Система построена на микросервисной архитектуре:

```
┌─────────────────────────────────────────────────────────────┐
│                    Python Controller                         │
│  - Управление сигнатурами                                   │
│  - Мониторинг                                               │
│  - Интерактивный интерфейс                                  │
└─────────────────────┬───────────────────────────────────────┘
                      │ REST API
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                     Go Engine                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Packet      │  │ Signature   │  │ Rate        │         │
│  │ Capture     │──│ Matching    │──│ Limiter     │         │
│  │ (gopacket)  │  │ (parallel)  │  │ (DoS det.)  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│         │              │                  │                  │
│         ▼              ▼                  ▼                  │
│  ┌─────────────────────────────────────────────────┐       │
│  │            Threat Handler                        │       │
│  │  - Logging  - IP Blocking  - Alerting           │       │
│  └─────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   SQLite Database                            │
│  - Signatures  - Threat Logs  - Statistics                  │
└─────────────────────────────────────────────────────────────┘
```

## Преимущества Go-движка

| Параметр | Python (старый) | Go (новый) | Улучшение |
|----------|-----------------|------------|-----------|
| Пропускная способность | ~12,350 пак/сек | ~150,000+ пак/сек | 12x |
| Задержка обработки | 1.2 мс | <0.1 мс | 12x |
| Потребление RAM | 120 МБ | 30 МБ | 4x |
| Многопоточность | Нет (GIL) | Да (goroutines) | ✓ |
| CPU эффективность | Низкая | Высокая | 3-4x |

## Быстрый старт

### Требования

- Go 1.21+
- Python 3.8+
- libpcap-dev
- SQLite3

### Установка (Ubuntu/Debian)

```bash
# Установка зависимостей
sudo apt-get update
sudo apt-get install -y golang libpcap-dev python3 python3-pip sqlite3

# Клонирование и сборка
cd signature-filter
make install-deps
make build
make init-db
```

### Запуск

```bash
# Терминал 1: Запуск движка (требует root для захвата пакетов)
sudo make run-engine INTERFACE=eth0

# Терминал 2: Мониторинг
make run-monitor

# Терминал 3: Тестирование
make test TARGET_HOST=192.168.1.10 TARGET_PORT=8080
```

## Структура проекта

```
signature-filter/
├── go-engine/           # Go-движок (высокая производительность)
│   ├── main.go          # Основной код движка
│   └── go.mod           # Зависимости Go
├── python-controller/   # Python контроллер (управление)
│   └── controller.py    # Управление и мониторинг
├── database/            # База данных
│   └── init_db.py       # Инициализация сигнатур
├── config/              # Конфигурация
│   └── config.json      # Настройки системы
├── tests/               # Тесты
│   └── test_attacks.py  # Генератор тестовых атак
├── Makefile             # Сборка и управление
└── README.md            # Документация
```

## API Endpoints

| Endpoint | Method | Описание |
|----------|--------|----------|
| `/api/health` | GET | Проверка состояния |
| `/api/stats` | GET | Статистика работы |
| `/api/signatures` | GET | Список сигнатур |
| `/api/signatures` | POST | Добавить сигнатуру |
| `/api/signatures/reload` | POST | Перезагрузить сигнатуры |
| `/api/block` | POST | Заблокировать IP |

### Примеры API

```bash
# Статистика
curl http://localhost:8080/api/stats

# Список сигнатур
curl http://localhost:8080/api/signatures

# Добавить сигнатуру
curl -X POST http://localhost:8080/api/signatures \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom_SQLi",
    "pattern": "(?i)select.*from",
    "pattern_type": "regex",
    "protocol": "TCP",
    "severity": 7,
    "description": "Custom SQL injection pattern"
  }'

# Заблокировать IP
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "duration_seconds": 300}'
```

## Конфигурация

```json
{
    "interface": "eth0",
    "database_path": "signatures.db",
    "api_port": 8080,
    "worker_count": 4,
    "buffer_size": 10000,
    "syn_threshold": 50,
    "http_threshold": 100,
    "udp_threshold": 200,
    "time_window_sec": 60,
    "enable_blocking": false
}
```

### Параметры

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `interface` | Сетевой интерфейс | eth0 |
| `worker_count` | Число обработчиков | 4 |
| `buffer_size` | Размер буфера пакетов | 10000 |
| `syn_threshold` | Порог SYN-пакетов/мин | 50 |
| `http_threshold` | Порог HTTP-запросов/мин | 100 |
| `udp_threshold` | Порог UDP-пакетов/мин | 200 |
| `enable_blocking` | Автоблокировка IP | false |

## Типы сигнатур

### Pattern Types

- **exact** - Точное совпадение строки
- **content** - Поиск подстроки (без учета регистра)
- **regex** - Регулярное выражение

### Пример сигнатуры

```json
{
    "name": "SQL_Union_Select",
    "pattern": "(?i)\\bunion\\s+(all\\s+)?select\\b",
    "pattern_type": "regex",
    "protocol": "TCP",
    "severity": 9,
    "description": "Detects UNION SELECT SQL injection"
}
```

## Обнаруживаемые угрозы

- **SQL Injection** - UNION, Time-based, Error-based, Boolean-based
- **XSS** - Reflected, Stored, DOM-based
- **Command Injection** - Shell commands, Path traversal
- **DoS/DDoS** - SYN flood, HTTP flood, UDP flood

## Тестирование

```bash
# Полный тест
make test

# Отдельные типы атак
make test-sqli      # SQL Injection
make test-xss       # XSS
make test-dos       # DoS атаки

# Ручной тест
python3 tests/test_attacks.py --full -t 192.168.1.10 -p 8080
```

## Развертывание на 2 VM

### VM1 - Сервер (анализатор)

```bash
# Установка
sudo apt-get install -y golang libpcap-dev
cd signature-filter
make build init-db

# Запуск
sudo ./build/signature-engine -interface eth0 -config config/config.json
```

### VM2 - Клиент (тестирование)

```bash
# Запуск тестов
python3 tests/test_attacks.py --full -t <VM1_IP> -p 8080
```

## Мониторинг

```bash
# Статистика в реальном времени
watch -n 1 'curl -s http://localhost:8080/api/stats | python3 -m json.tool'

# Логи
tail -f /var/log/signature-engine.log
```

## Лицензия

Разработано в рамках НИР "Алгоритм адаптивной фильтрации информационных потоков в корпоративной вычислительной сети"

НИЯУ МИФИ, Кафедра Криптологии и кибербезопасности, 2025
