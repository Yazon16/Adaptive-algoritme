#!/usr/bin/env python3
"""
Python Controller для Adaptive Signature Engine
Управление Go-движком через API и дополнительные функции
"""

import json
import sqlite3
import requests
import subprocess
import sys
import time
import os
import signal
import logging
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

# Конфигурация логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SignatureController')


@dataclass
class Signature:
    """Структура сигнатуры"""
    name: str
    pattern: str
    pattern_type: str  # exact, regex, content
    protocol: str      # TCP, UDP, ICMP, ALL
    severity: int
    description: str = ""
    id: int = 0


class SignatureDatabase:
    """Менеджер базы данных сигнатур"""
    
    def __init__(self, db_path: str = "signatures.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
    
    def _init_db(self):
        """Инициализация структуры БД"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                pattern TEXT NOT NULL,
                pattern_type TEXT CHECK(pattern_type IN ('exact', 'regex', 'content')),
                protocol TEXT CHECK(protocol IN ('TCP', 'UDP', 'ICMP', 'ALL')),
                severity INTEGER CHECK(severity BETWEEN 1 AND 10),
                description TEXT,
                enabled BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица для логов угроз
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature_id INTEGER,
                signature_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                matched_content TEXT,
                confidence REAL,
                threat_type TEXT,
                severity INTEGER
            )
        ''')
        
        self.conn.commit()
    
    def add_signature(self, sig: Signature) -> bool:
        """Добавление сигнатуры"""
        try:
            self.conn.execute('''
                INSERT INTO signatures (name, pattern, pattern_type, protocol, severity, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (sig.name, sig.pattern, sig.pattern_type, sig.protocol, sig.severity, sig.description))
            self.conn.commit()
            logger.info(f"Сигнатура '{sig.name}' добавлена")
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"Сигнатура '{sig.name}' уже существует")
            return False
    
    def get_signatures(self, enabled_only: bool = True) -> List[Signature]:
        """Получение списка сигнатур"""
        query = "SELECT id, name, pattern, pattern_type, protocol, severity, description FROM signatures"
        if enabled_only:
            query += " WHERE enabled = 1"
        
        cursor = self.conn.execute(query)
        return [Signature(
            id=row[0],
            name=row[1],
            pattern=row[2],
            pattern_type=row[3],
            protocol=row[4],
            severity=row[5],
            description=row[6]
        ) for row in cursor.fetchall()]
    
    def delete_signature(self, sig_id: int) -> bool:
        """Удаление сигнатуры"""
        cursor = self.conn.execute("DELETE FROM signatures WHERE id = ?", (sig_id,))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def toggle_signature(self, sig_id: int, enabled: bool) -> bool:
        """Включение/отключение сигнатуры"""
        cursor = self.conn.execute(
            "UPDATE signatures SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, sig_id)
        )
        self.conn.commit()
        return cursor.rowcount > 0
    
    def log_threat(self, threat: Dict[str, Any]):
        """Логирование угрозы в БД"""
        self.conn.execute('''
            INSERT INTO threat_logs 
            (signature_id, signature_name, source_ip, dest_ip, source_port, dest_port,
             protocol, matched_content, confidence, threat_type, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat.get('signature_id'),
            threat.get('signature_name'),
            threat.get('source_ip'),
            threat.get('dest_ip'),
            threat.get('source_port'),
            threat.get('dest_port'),
            threat.get('protocol'),
            threat.get('matched_content', '')[:500],
            threat.get('confidence'),
            threat.get('threat_type'),
            threat.get('severity')
        ))
        self.conn.commit()
    
    def get_threat_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Статистика угроз за период"""
        cursor = self.conn.execute('''
            SELECT 
                threat_type,
                COUNT(*) as count,
                AVG(severity) as avg_severity
            FROM threat_logs
            WHERE timestamp > datetime('now', ? || ' hours')
            GROUP BY threat_type
        ''', (f'-{hours}',))
        
        stats = {}
        for row in cursor.fetchall():
            stats[row[0]] = {
                'count': row[1],
                'avg_severity': round(row[2], 2)
            }
        return stats
    
    def close(self):
        """Закрытие соединения"""
        self.conn.close()


class EngineController:
    """Контроллер для управления Go-движком"""
    
    def __init__(self, api_url: str = "http://localhost:8080"):
        self.api_url = api_url
        self.process = None
    
    def start_engine(self, config_path: str, interface: str = None, 
                     engine_binary: str = "./signature-engine") -> bool:
        """Запуск Go-движка"""
        cmd = [engine_binary, "-config", config_path]
        if interface:
            cmd.extend(["-interface", interface])
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(2)  # Ожидание запуска
            
            if self.process.poll() is None:
                logger.info("Go-движок успешно запущен")
                return True
            else:
                stderr = self.process.stderr.read().decode()
                logger.error(f"Ошибка запуска движка: {stderr}")
                return False
        except FileNotFoundError:
            logger.error(f"Исполняемый файл не найден: {engine_binary}")
            return False
    
    def stop_engine(self):
        """Остановка Go-движка"""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
            logger.info("Go-движок остановлен")
    
    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Получение статистики от движка"""
        try:
            response = requests.get(f"{self.api_url}/api/stats", timeout=5)
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Ошибка получения статистики: {e}")
            return None
    
    def reload_signatures(self) -> bool:
        """Перезагрузка сигнатур в движке"""
        try:
            response = requests.post(f"{self.api_url}/api/signatures/reload", timeout=5)
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Ошибка перезагрузки сигнатур: {e}")
            return False
    
    def add_signature_via_api(self, sig: Signature) -> bool:
        """Добавление сигнатуры через API"""
        try:
            response = requests.post(
                f"{self.api_url}/api/signatures",
                json=asdict(sig),
                timeout=5
            )
            return response.status_code == 201
        except requests.RequestException as e:
            logger.error(f"Ошибка добавления сигнатуры: {e}")
            return False
    
    def block_ip(self, ip: str, duration_seconds: int = 300) -> bool:
        """Блокировка IP адреса"""
        try:
            response = requests.post(
                f"{self.api_url}/api/block",
                json={"ip": ip, "duration_seconds": duration_seconds},
                timeout=5
            )
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Ошибка блокировки IP: {e}")
            return False
    
    def health_check(self) -> bool:
        """Проверка состояния движка"""
        try:
            response = requests.get(f"{self.api_url}/api/health", timeout=2)
            return response.status_code == 200
        except requests.RequestException:
            return False


def populate_default_signatures(db: SignatureDatabase):
    """Заполнение БД стандартными сигнатурами для тестирования"""
    
    default_signatures = [
        # SQL Injection сигнатуры
        Signature(
            name="SQL Union Basic",
            pattern=r"(?i)\bunion\s+select\b",
            pattern_type="regex",
            protocol="TCP",
            severity=9,
            description="Basic UNION SELECT injection detection"
        ),
        Signature(
            name="SQL Time-Based",
            pattern=r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor)\s*\(",
            pattern_type="regex",
            protocol="TCP",
            severity=9,
            description="Time-delay functions detection"
        ),
        Signature(
            name="SQL Error-Based",
            pattern=r"(?i)\b(?:convert|cast|extractvalue|updatexml)\s*\(",
            pattern_type="regex",
            protocol="TCP",
            severity=8,
            description="Error-based SQL patterns"
        ),
        Signature(
            name="SQL System Access",
            pattern=r"(?i)\b(?:information_schema|pg_catalog|sys\.|mysql\.)",
            pattern_type="regex",
            protocol="TCP",
            severity=7,
            description="System table/database access"
        ),
        Signature(
            name="SQL Comments",
            pattern=r"(?i)(['\"]\s*--|['\"]\s*#|/\*.*?\*/)",
            pattern_type="regex",
            protocol="TCP",
            severity=6,
            description="SQL comments after quote"
        ),
        
        # XSS сигнатуры
        Signature(
            name="XSS Script Tag",
            pattern=r"(?i)<script[^>]*>",
            pattern_type="regex",
            protocol="TCP",
            severity=8,
            description="Basic script tag injection"
        ),
        Signature(
            name="XSS Event Handler",
            pattern=r"(?i)on(?:load|error|click|mouseover|focus)\s*=",
            pattern_type="regex",
            protocol="TCP",
            severity=7,
            description="JavaScript event handler injection"
        ),
        Signature(
            name="XSS JavaScript Protocol",
            pattern=r"(?i)javascript\s*:",
            pattern_type="regex",
            protocol="TCP",
            severity=7,
            description="JavaScript protocol handler"
        ),
        
        # Command Injection сигнатуры
        Signature(
            name="Command Injection Basic",
            pattern=r";\s*(?:cat|ls|wget|curl|bash|sh|nc)\s",
            pattern_type="regex",
            protocol="TCP",
            severity=9,
            description="Basic command injection patterns"
        ),
        Signature(
            name="Path Traversal",
            pattern=r"\.\./\.\./",
            pattern_type="content",
            protocol="TCP",
            severity=8,
            description="Directory traversal attempt"
        ),
    ]
    
    added = 0
    for sig in default_signatures:
        if db.add_signature(sig):
            added += 1
    
    logger.info(f"Добавлено {added} сигнатур из {len(default_signatures)}")
    return added


def create_config(config_path: str, interface: str = "eth0", 
                  db_path: str = "signatures.db", api_port: int = 8080):
    """Создание конфигурационного файла"""
    config = {
        "interface": interface,
        "database_path": db_path,
        "api_port": api_port,
        "worker_count": 4,
        "buffer_size": 10000,
        "syn_threshold": 50,
        "http_threshold": 100,
        "udp_threshold": 200,
        "time_window_sec": 60,
        "enable_blocking": False
    }
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"Конфигурация сохранена в {config_path}")
    return config_path


def monitor_engine(controller: EngineController, interval: int = 10):
    """Мониторинг работы движка"""
    logger.info("Запуск мониторинга движка...")
    
    try:
        while True:
            if controller.health_check():
                stats = controller.get_stats()
                if stats:
                    logger.info(
                        f"Packets: {stats.get('packets_processed', 0)} | "
                        f"Threats: {stats.get('threats_detected', 0)} | "
                        f"Dropped: {stats.get('packets_dropped', 0)} | "
                        f"Uptime: {stats.get('uptime_seconds', 0):.0f}s"
                    )
            else:
                logger.warning("Движок не отвечает!")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Мониторинг остановлен")


def interactive_mode(db: SignatureDatabase, controller: EngineController):
    """Интерактивный режим управления"""
    print("\n=== Adaptive Signature Engine Controller ===")
    print("Команды: stats, sigs, add, delete, reload, block, quit")
    
    while True:
        try:
            cmd = input("\n> ").strip().lower()
            
            if cmd == "quit" or cmd == "exit":
                break
            
            elif cmd == "stats":
                stats = controller.get_stats()
                if stats:
                    print(json.dumps(stats, indent=2))
                else:
                    print("Не удалось получить статистику")
            
            elif cmd == "sigs":
                sigs = db.get_signatures()
                for sig in sigs:
                    status = "✓" if True else "✗"
                    print(f"[{sig.id}] {status} {sig.name} ({sig.pattern_type}) - Severity: {sig.severity}")
            
            elif cmd == "add":
                print("Добавление новой сигнатуры:")
                name = input("  Name: ")
                pattern = input("  Pattern: ")
                ptype = input("  Type (exact/regex/content): ")
                protocol = input("  Protocol (TCP/UDP/ICMP/ALL): ").upper()
                severity = int(input("  Severity (1-10): "))
                description = input("  Description: ")
                
                sig = Signature(name, pattern, ptype, protocol, severity, description)
                if db.add_signature(sig):
                    controller.reload_signatures()
                    print("Сигнатура добавлена")
            
            elif cmd == "delete":
                sig_id = int(input("  Signature ID: "))
                if db.delete_signature(sig_id):
                    controller.reload_signatures()
                    print("Сигнатура удалена")
                else:
                    print("Сигнатура не найдена")
            
            elif cmd == "reload":
                if controller.reload_signatures():
                    print("Сигнатуры перезагружены")
                else:
                    print("Ошибка перезагрузки")
            
            elif cmd == "block":
                ip = input("  IP address: ")
                duration = int(input("  Duration (seconds): "))
                if controller.block_ip(ip, duration):
                    print(f"IP {ip} заблокирован")
                else:
                    print("Ошибка блокировки")
            
            elif cmd == "help":
                print("Доступные команды:")
                print("  stats   - Статистика движка")
                print("  sigs    - Список сигнатур")
                print("  add     - Добавить сигнатуру")
                print("  delete  - Удалить сигнатуру")
                print("  reload  - Перезагрузить сигнатуры")
                print("  block   - Заблокировать IP")
                print("  quit    - Выход")
            
            else:
                print("Неизвестная команда. Введите 'help' для справки.")
        
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Ошибка: {e}")


def main():
    parser = argparse.ArgumentParser(description='Adaptive Signature Engine Controller')
    parser.add_argument('-c', '--config', default='config.json', help='Путь к конфигурации')
    parser.add_argument('-d', '--database', default='signatures.db', help='Путь к БД сигнатур')
    parser.add_argument('-i', '--interface', default='eth0', help='Сетевой интерфейс')
    parser.add_argument('-p', '--port', type=int, default=8080, help='API порт')
    parser.add_argument('--init-db', action='store_true', help='Инициализация БД сигнатурами')
    parser.add_argument('--start', action='store_true', help='Запуск движка')
    parser.add_argument('--monitor', action='store_true', help='Режим мониторинга')
    parser.add_argument('--interactive', action='store_true', help='Интерактивный режим')
    parser.add_argument('--engine-path', default='./signature-engine', help='Путь к Go-движку')
    
    args = parser.parse_args()
    
    # Инициализация компонентов
    db = SignatureDatabase(args.database)
    controller = EngineController(f"http://localhost:{args.port}")
    
    try:
        # Инициализация БД сигнатурами
        if args.init_db:
            populate_default_signatures(db)
        
        # Создание конфигурации
        create_config(args.config, args.interface, args.database, args.port)
        
        # Запуск движка
        if args.start:
            if not controller.start_engine(args.config, args.interface, args.engine_path):
                logger.error("Не удалось запустить движок")
                sys.exit(1)
        
        # Режим мониторинга
        if args.monitor:
            monitor_engine(controller)
        
        # Интерактивный режим
        elif args.interactive:
            interactive_mode(db, controller)
        
        # Если не указан режим, просто показываем статистику
        elif not args.init_db and not args.start:
            if controller.health_check():
                stats = controller.get_stats()
                print(json.dumps(stats, indent=2))
            else:
                print("Движок не запущен или не отвечает")
    
    finally:
        if args.start:
            controller.stop_engine()
        db.close()


if __name__ == "__main__":
    main()
