# Makefile для Adaptive Signature Filter
# Микросервисная архитектура с Go-движком

.PHONY: all build clean install test init-db run-engine run-controller

# Переменные
GO_ENGINE_DIR = go-engine
PYTHON_DIR = python-controller
DB_DIR = database
CONFIG_DIR = config
BUILD_DIR = build
BIN_NAME = signature-engine
DB_PATH = signatures.db
CONFIG_PATH = config/config.json

# Значения по умолчанию
INTERFACE ?= eth0
API_PORT ?= 8080
TARGET_HOST ?= 127.0.0.1
TARGET_PORT ?= 8081

# Сборка всего проекта
all: build init-db

# Сборка Go-движка
build: $(BUILD_DIR)
	@echo "==> Сборка Go-движка..."
	cd $(GO_ENGINE_DIR) && \
		go mod download && \
		CGO_ENABLED=1 go build -o ../$(BUILD_DIR)/$(BIN_NAME) .
	@echo "==> Сборка завершена: $(BUILD_DIR)/$(BIN_NAME)"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Инициализация базы данных
init-db:
	@echo "==> Инициализация базы данных сигнатур..."
	python3 $(DB_DIR)/init_db.py -d $(DB_PATH) --show
	@echo "==> База данных готова"

# Очистка
clean:
	@echo "==> Очистка..."
	rm -rf $(BUILD_DIR)
	rm -f $(DB_PATH)
	rm -f *.log
	@echo "==> Очистка завершена"

# Установка зависимостей
install-deps:
	@echo "==> Установка зависимостей..."
	# Go зависимости
	cd $(GO_ENGINE_DIR) && go mod download
	# Python зависимости
	pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests
	# Behavioral модуль зависимости
	pip3 install scikit-learn numpy joblib --break-system-packages 2>/dev/null || pip3 install scikit-learn numpy joblib
	# Системные зависимости для libpcap
	@echo "ВНИМАНИЕ: Для сборки требуются libpcap-dev и gcc"
	@echo "Ubuntu/Debian: sudo apt-get install libpcap-dev gcc"
	@echo "CentOS/RHEL: sudo yum install libpcap-devel gcc"

# ============================================================
# BEHAVIORAL MODULE
# ============================================================

BEHAVIORAL_DIR = behavioral-module
BEHAVIORAL_PORT ?= 8081

# Запуск behavioral модуля
run-behavioral:
	@echo "==> Запуск модуля поведенческого анализа на порту $(BEHAVIORAL_PORT)..."
	cd $(BEHAVIORAL_DIR) && python3 main.py --port $(BEHAVIORAL_PORT)

# Запуск behavioral с логированием
run-behavioral-log:
	@echo "==> Логи: behavioral.log"
	cd $(BEHAVIORAL_DIR) && python3 main.py --port $(BEHAVIORAL_PORT) 2>&1 | tee behavioral.log

# Запуск behavioral в фоне
run-behavioral-bg:
	@echo "==> Behavioral модуль запущен в фоне на порту $(BEHAVIORAL_PORT)"
	@cd $(BEHAVIORAL_DIR) && python3 main.py --port $(BEHAVIORAL_PORT) > behavioral.log 2>&1 &
	@sleep 1
	@echo "==> PID: $$(pgrep -f 'python3 main.py')"

# Остановка behavioral модуля
stop-behavioral:
	@echo "==> Остановка behavioral модуля..."
	@pkill -f "python3 main.py" || echo "Модуль не запущен"

# Статус behavioral модуля
behavioral-status:
	@curl -s http://localhost:$(BEHAVIORAL_PORT)/api/health 2>/dev/null && echo "" || echo "Модуль не отвечает"
	@curl -s http://localhost:$(BEHAVIORAL_PORT)/api/stats 2>/dev/null | python3 -m json.tool || true

# Обучение ML модели
behavioral-train:
	@echo "==> Обучение ML модели..."
	@curl -X POST http://localhost:$(BEHAVIORAL_PORT)/api/train | python3 -m json.tool

# Обновление baseline
behavioral-baseline:
	@echo "==> Обновление baseline..."
	@curl -X POST http://localhost:$(BEHAVIORAL_PORT)/api/baseline/update

# Тест behavioral API
behavioral-test:
	@echo "==> Тест behavioral API..."
	@echo "Health:"
	@curl -s http://localhost:$(BEHAVIORAL_PORT)/api/health
	@echo "\n\nAnalyze test:"
	@curl -s -X POST http://localhost:$(BEHAVIORAL_PORT)/api/analyze \
		-H "Content-Type: application/json" \
		-d '{"src_ip": "192.168.1.100", "signature_score": 0.0}' | python3 -m json.tool

# ============================================================
# ПОЛНЫЙ ЗАПУСК (оба модуля)
# ============================================================

# Запуск всей системы
run-all: build init-db
	@echo "==> Запуск полной системы..."
	@echo "1. Запуск Go-движка..."
	@sudo $(BUILD_DIR)/$(BIN_NAME) -config $(CONFIG_PATH) -interface $(INTERFACE) > engine.log 2>&1 &
	@sleep 2
	@echo "2. Запуск Behavioral модуля..."
	@cd $(BEHAVIORAL_DIR) && python3 main.py --port $(BEHAVIORAL_PORT) > behavioral.log 2>&1 &
	@sleep 1
	@echo ""
	@echo "==> Система запущена:"
	@echo "    Go Engine:  http://localhost:$(API_PORT)"
	@echo "    Behavioral: http://localhost:$(BEHAVIORAL_PORT)"
	@echo ""
	@echo "Для остановки: make stop-all"

# Остановка всей системы
stop-all:
	@echo "==> Остановка системы..."
	@sudo pkill -f signature-engine || true
	@pkill -f "python3 main.py" || true
	@echo "==> Система остановлена"

# Запуск Go-движка
run-engine: build init-db
	@echo "==> Запуск движка сигнатурного анализа..."
	sudo $(BUILD_DIR)/$(BIN_NAME) -config $(CONFIG_PATH) -interface $(INTERFACE)

# Запуск движка с логированием в файл
run-engine-log: build init-db
	@echo "==> Логи записываются в: engine.log"
	@echo "==> Ctrl+C для остановки"
	sudo $(BUILD_DIR)/$(BIN_NAME) -config $(CONFIG_PATH) -interface $(INTERFACE) 2>&1 | tee engine.log

# Запуск движка в фоне с логами
run-engine-bg: build init-db
	@echo "==> Движок запущен в фоне. Логи: engine.log"
	@echo "==> Для остановки: sudo pkill signature-engine"
	@sudo $(BUILD_DIR)/$(BIN_NAME) -config $(CONFIG_PATH) -interface $(INTERFACE) > engine.log 2>&1 &
	@sleep 1
	@echo "==> PID: $$(pgrep -f signature-engine)"

# Остановка движка
stop-engine:
	@echo "==> Остановка движка..."
	@sudo pkill -f signature-engine || echo "Движок не запущен"

# Просмотр логов в реальном времени
logs:
	@tail -f engine.log

# Просмотр последних 50 угроз
logs-threats:
	@grep "\[THREAT\]" engine.log | tail -50

# Подсчёт обнаруженных угроз
logs-stats:
	@echo "==> Статистика обнаруженных угроз:"
	@echo -n "  SQL Injection: " && grep -c "SQLI\|SQL" engine.log 2>/dev/null || echo "0"
	@echo -n "  XSS:           " && grep -c "XSS" engine.log 2>/dev/null || echo "0"
	@echo -n "  DoS/Flood:     " && grep -c "DOS\|Flood" engine.log 2>/dev/null || echo "0"
	@echo -n "  Всего угроз:   " && grep -c "\[THREAT\]" engine.log 2>/dev/null || echo "0"

# Запуск Python контроллера
run-controller:
	@echo "==> Запуск Python контроллера..."
	python3 $(PYTHON_DIR)/controller.py --interactive -d $(DB_PATH) -p $(API_PORT)

# Запуск мониторинга
run-monitor:
	@echo "==> Запуск мониторинга..."
	python3 $(PYTHON_DIR)/controller.py --monitor -d $(DB_PATH) -p $(API_PORT)

# Запуск тестового сервера
run-test-server:
	@echo "==> Запуск тестового HTTP сервера на порту $(TARGET_PORT)..."
	python3 tests/test_attacks.py --server -p $(TARGET_PORT)

# Запуск полного теста
test: 
	@echo "==> Запуск полного цикла тестирования..."
	python3 tests/test_attacks.py --full -t $(TARGET_HOST) -p $(TARGET_PORT)

# Стресс-тест (длительный интенсивный тест)
DURATION ?= 60
INTENSITY ?= medium

stress-test:
	@echo "==> Запуск стресс-теста ($(DURATION)с, интенсивность: $(INTENSITY))..."
	python3 tests/stress_test.py -t $(TARGET_HOST) -p $(TARGET_PORT) -d $(DURATION) -i $(INTENSITY)

stress-test-low:
	python3 tests/stress_test.py -t $(TARGET_HOST) -p $(TARGET_PORT) -d 60 -i low

stress-test-medium:
	python3 tests/stress_test.py -t $(TARGET_HOST) -p $(TARGET_PORT) -d 120 -i medium

stress-test-high:
	python3 tests/stress_test.py -t $(TARGET_HOST) -p $(TARGET_PORT) -d 180 -i high

stress-test-extreme:
	python3 tests/stress_test.py -t $(TARGET_HOST) -p $(TARGET_PORT) -d 300 -i extreme

# Тест SQL Injection
test-sqli:
	@echo "==> Тестирование SQL Injection..."
	python3 tests/test_attacks.py --sqli 10 -t $(TARGET_HOST) -p $(TARGET_PORT)

# Тест XSS
test-xss:
	@echo "==> Тестирование XSS..."
	python3 tests/test_attacks.py --xss 10 -t $(TARGET_HOST) -p $(TARGET_PORT)

# Тест DoS
test-dos:
	@echo "==> Тестирование DoS..."
	python3 tests/test_attacks.py --syn 200 --http 100 -t $(TARGET_HOST) -p $(TARGET_PORT)

# Проверка состояния движка
status:
	@echo "==> Проверка состояния движка..."
	@curl -s http://localhost:$(API_PORT)/api/health 2>/dev/null && echo " - Движок работает" || echo "Движок не отвечает"
	@echo ""
	@curl -s http://localhost:$(API_PORT)/api/stats 2>/dev/null | python3 -m json.tool || true

# Перезагрузка сигнатур
reload-sigs:
	@echo "==> Перезагрузка сигнатур..."
	@curl -X POST http://localhost:$(API_PORT)/api/signatures/reload

# Показать сигнатуры
show-sigs:
	@echo "==> Список сигнатур..."
	@curl -s http://localhost:$(API_PORT)/api/signatures | python3 -m json.tool

# Помощь
help:
	@echo "Adaptive Signature Filter - Makefile"
	@echo ""
	@echo "СБОРКА И УСТАНОВКА:"
	@echo "  make build          - Сборка Go-движка"
	@echo "  make init-db        - Инициализация БД сигнатур"
	@echo "  make install-deps   - Установка зависимостей"
	@echo "  make clean          - Очистка"
	@echo ""
	@echo "ЗАПУСК ДВИЖКА:"
	@echo "  make run-engine     - Запуск (вывод в консоль)"
	@echo "  make run-engine-log - Запуск с логами в файл engine.log"
	@echo "  make run-engine-bg  - Запуск в фоновом режиме"
	@echo "  make stop-engine    - Остановка движка"
	@echo ""
	@echo "ЛОГИ:"
	@echo "  make logs           - Просмотр логов в реальном времени"
	@echo "  make logs-threats   - Последние 50 обнаруженных угроз"
	@echo "  make logs-stats     - Статистика по типам угроз"
	@echo ""
	@echo "ТЕСТИРОВАНИЕ:"
	@echo "  make test           - Быстрый тест (25 пакетов)"
	@echo "  make stress-test    - Стресс-тест (настраиваемый)"
	@echo "  make stress-test-low     - 60 сек, низкая нагрузка"
	@echo "  make stress-test-medium  - 120 сек, средняя нагрузка"
	@echo "  make stress-test-high    - 180 сек, высокая нагрузка"
	@echo "  make stress-test-extreme - 300 сек, экстремальная нагрузка"
	@echo ""
	@echo "МОНИТОРИНГ:"
	@echo "  make status         - Состояние движка (API)"
	@echo "  make show-sigs      - Список сигнатур"
	@echo "  make run-monitor    - Интерактивный мониторинг"
	@echo ""
	@echo "ПЕРЕМЕННЫЕ:"
	@echo "  INTERFACE=$(INTERFACE)      - Сетевой интерфейс"
	@echo "  TARGET_HOST=$(TARGET_HOST)  - IP цели для тестов"
	@echo "  TARGET_PORT=$(TARGET_PORT)  - Порт цели"
	@echo "  DURATION=$(DURATION)        - Длительность стресс-теста (сек)"
	@echo "  INTENSITY=$(INTENSITY)      - Интенсивность (low/medium/high/extreme)"
	@echo ""
	@echo "ПРИМЕРЫ:"
	@echo "  make run-engine-log INTERFACE=enp0s8"
	@echo "  make stress-test TARGET_HOST=192.168.100.1 DURATION=300 INTENSITY=high"
