#!/usr/bin/env python3
"""
Скрипт инициализации базы данных сигнатур
Создает БД SQLite с 10+ тестовыми сигнатурами для различных типов атак
"""

import sqlite3
import os
import sys

# Путь к базе данных
DB_PATH = os.environ.get('SIGNATURES_DB', 'signatures.db')

# Тестовые сигнатуры (10 записей для различных типов атак)
TEST_SIGNATURES = [
    # SQL Injection сигнатуры
    {
        "name": "SQL_Union_Select",
        "pattern": r"(?i)\bunion\s+(all\s+)?select\b",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 9,
        "description": "Detects UNION SELECT SQL injection attempts"
    },
    {
        "name": "SQL_Time_Based",
        "pattern": r"(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 9,
        "description": "Detects time-based blind SQL injection using delay functions"
    },
    {
        "name": "SQL_Error_Based",
        "pattern": r"(?i)\b(extractvalue|updatexml|xmltype|dbms_pipe)\s*\(",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 8,
        "description": "Detects error-based SQL injection techniques"
    },
    {
        "name": "SQL_System_Tables",
        "pattern": r"(?i)(information_schema|pg_catalog|sysobjects|syscolumns|mysql\.user)",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 7,
        "description": "Detects access to system tables and metadata"
    },
    
    # XSS сигнатуры
    {
        "name": "XSS_Script_Tag",
        "pattern": r"(?i)<script[^>]*(?:>|src\s*=)",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 8,
        "description": "Detects script tag injection attempts"
    },
    {
        "name": "XSS_Event_Handler",
        "pattern": r"(?i)\bon(load|error|click|mouseover|focus|blur|submit)\s*=\s*['\"]?",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 7,
        "description": "Detects JavaScript event handler injection"
    },
    {
        "name": "XSS_Javascript_Protocol",
        "pattern": r"(?i)javascript\s*:\s*[^void]",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 7,
        "description": "Detects javascript: protocol handler abuse"
    },
    
    # Command Injection сигнатуры
    {
        "name": "CMD_Basic_Injection",
        "pattern": r"[;&|`]\s*(cat|ls|wget|curl|bash|sh|nc|netcat|whoami|id|uname)\s",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 9,
        "description": "Detects basic command injection patterns"
    },
    {
        "name": "CMD_Path_Traversal",
        "pattern": "../../../",
        "pattern_type": "content",
        "protocol": "TCP",
        "severity": 8,
        "description": "Detects directory traversal attempts"
    },
    
    # Other signatures
    {
        "name": "HTTP_Admin_Access",
        "pattern": r"/admin|/wp-admin|/phpmyadmin|/manager",
        "pattern_type": "regex",
        "protocol": "TCP",
        "severity": 5,
        "description": "Detects access to common admin panels"
    },
]


def init_database(db_path: str):
    """Инициализация базы данных"""
    print(f"Инициализация базы данных: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Создание таблицы сигнатур
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            pattern TEXT NOT NULL,
            pattern_type TEXT CHECK(pattern_type IN ('exact', 'regex', 'content')),
            protocol TEXT CHECK(protocol IN ('TCP', 'UDP', 'ICMP', 'ALL')),
            severity INTEGER CHECK(severity BETWEEN 1 AND 10),
            description TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Создание таблицы логов угроз
    cursor.execute('''
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
            severity INTEGER,
            FOREIGN KEY (signature_id) REFERENCES signatures(id)
        )
    ''')
    
    # Создание индексов для ускорения запросов
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_signatures_enabled ON signatures(enabled)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_signatures_protocol ON signatures(protocol)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_logs_timestamp ON threat_logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_logs_source_ip ON threat_logs(source_ip)')
    
    conn.commit()
    print("Таблицы созданы успешно")
    
    return conn


def populate_signatures(conn: sqlite3.Connection):
    """Заполнение БД тестовыми сигнатурами"""
    cursor = conn.cursor()
    
    added = 0
    skipped = 0
    
    for sig in TEST_SIGNATURES:
        try:
            cursor.execute('''
                INSERT INTO signatures (name, pattern, pattern_type, protocol, severity, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                sig['name'],
                sig['pattern'],
                sig['pattern_type'],
                sig['protocol'],
                sig['severity'],
                sig['description']
            ))
            added += 1
            print(f"  [+] Добавлена: {sig['name']}")
        except sqlite3.IntegrityError:
            skipped += 1
            print(f"  [=] Уже существует: {sig['name']}")
    
    conn.commit()
    print(f"\nИтого: добавлено {added}, пропущено {skipped}")
    
    return added


def show_signatures(conn: sqlite3.Connection):
    """Вывод списка сигнатур"""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, pattern_type, protocol, severity, enabled
        FROM signatures
        ORDER BY severity DESC, name
    ''')
    
    print("\n" + "="*80)
    print(f"{'ID':<4} {'Name':<25} {'Type':<10} {'Proto':<6} {'Sev':<4} {'Status'}")
    print("="*80)
    
    for row in cursor.fetchall():
        status = "✓ ON" if row[5] else "✗ OFF"
        print(f"{row[0]:<4} {row[1]:<25} {row[2]:<10} {row[3]:<6} {row[4]:<4} {status}")
    
    print("="*80)


def export_signatures(conn: sqlite3.Connection, output_file: str):
    """Экспорт сигнатур в JSON"""
    import json
    
    cursor = conn.cursor()
    cursor.execute('''
        SELECT name, pattern, pattern_type, protocol, severity, description
        FROM signatures WHERE enabled = 1
    ''')
    
    signatures = []
    for row in cursor.fetchall():
        signatures.append({
            "name": row[0],
            "pattern": row[1],
            "pattern_type": row[2],
            "protocol": row[3],
            "severity": row[4],
            "description": row[5]
        })
    
    with open(output_file, 'w') as f:
        json.dump(signatures, f, indent=2)
    
    print(f"Экспортировано {len(signatures)} сигнатур в {output_file}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Инициализация базы данных сигнатур')
    parser.add_argument('-d', '--database', default=DB_PATH, help='Путь к БД')
    parser.add_argument('--show', action='store_true', help='Показать сигнатуры')
    parser.add_argument('--export', type=str, help='Экспорт в JSON файл')
    parser.add_argument('--force', action='store_true', help='Пересоздать БД')
    
    args = parser.parse_args()
    
    # Удаление старой БД если указан --force
    if args.force and os.path.exists(args.database):
        os.remove(args.database)
        print(f"Удалена старая БД: {args.database}")
    
    # Инициализация
    conn = init_database(args.database)
    
    # Заполнение сигнатурами
    populate_signatures(conn)
    
    # Показать сигнатуры
    if args.show:
        show_signatures(conn)
    
    # Экспорт
    if args.export:
        export_signatures(conn, args.export)
    
    conn.close()
    print(f"\nБаза данных готова: {args.database}")


if __name__ == "__main__":
    main()
