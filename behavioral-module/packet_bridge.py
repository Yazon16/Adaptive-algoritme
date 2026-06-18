#!/usr/bin/env python3
"""
Packet Bridge - Мост между сетевым трафиком и Behavioral модулем

Захватывает пакеты с сетевого интерфейса и отправляет в API
для анализа поведенческим модулем.

Использование:
    sudo python3 packet_bridge.py enp0s8
    sudo python3 packet_bridge.py eth0 --api http://localhost:8081
"""

import argparse
import sys
import time
import signal
import threading
from collections import deque

try:
    import requests
except ImportError:
    print("Установите requests: pip3 install requests --break-system-packages")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("Установите scapy: pip3 install scapy --break-system-packages")
    sys.exit(1)


class PacketBridge:
    """Мост для передачи пакетов в Behavioral API"""
    
    def __init__(self, interface: str, api_url: str, batch_size: int = 10):
        self.interface = interface
        self.api_url = api_url.rstrip('/')
        self.batch_size = batch_size
        
        self.running = True
        self.packet_buffer = deque(maxlen=1000)
        self.lock = threading.Lock()
        
        # Статистика
        self.packets_captured = 0
        self.packets_sent = 0
        self.errors = 0
        self.start_time = time.time()
        
        # Фоновый отправщик
        self.sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
    
    def start(self):
        """Запуск моста"""
        print(f"=" * 60)
        print(f"Packet Bridge Started")
        print(f"=" * 60)
        print(f"Interface:    {self.interface}")
        print(f"Behavioral API: {self.api_url}")
        print(f"Batch size:   {self.batch_size}")
        print(f"=" * 60)
        print(f"Press Ctrl+C to stop\n")
        
        # Запуск отправщика
        self.sender_thread.start()
        
        # Захват пакетов
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"\nError: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Остановка моста"""
        self.running = False
        print(f"\n{'=' * 60}")
        print(f"Packet Bridge Stopped")
        print(f"{'=' * 60}")
        self._print_stats()
    
    def _process_packet(self, packet):
        """Обработка захваченного пакета"""
        if IP not in packet:
            return
        
        self.packets_captured += 1
        
        ip_layer = packet[IP]
        
        packet_data = {
            "timestamp": float(time.time()),
            "src_ip": str(ip_layer.src),
            "dst_ip": str(ip_layer.dst),
            "protocol": "OTHER",
            "size": int(len(packet)),
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0,
            "payload": "",
        }
        
        # TCP
        if TCP in packet:
            tcp = packet[TCP]
            packet_data["protocol"] = "TCP"
            packet_data["src_port"] = int(tcp.sport)
            packet_data["dst_port"] = int(tcp.dport)
            packet_data["tcp_flags"] = int(tcp.flags)
            
            # Payload
            if Raw in packet:
                try:
                    raw_data = bytes(packet[Raw].load)[:500]
                    packet_data["payload"] = raw_data.decode('utf-8', errors='ignore')
                except:
                    pass
        
        # UDP
        elif UDP in packet:
            udp = packet[UDP]
            packet_data["protocol"] = "UDP"
            packet_data["src_port"] = int(udp.sport)
            packet_data["dst_port"] = int(udp.dport)
        
        # ICMP
        elif ICMP in packet:
            packet_data["protocol"] = "ICMP"
        
        # Добавляем в буфер
        with self.lock:
            self.packet_buffer.append(packet_data)
        
        # Вывод
        if self.packets_captured % 100 == 0:
            self._print_status()
    
    def _sender_loop(self):
        """Фоновый цикл отправки пакетов"""
        while self.running:
            try:
                packets_to_send = []
                
                with self.lock:
                    while self.packet_buffer and len(packets_to_send) < self.batch_size:
                        packets_to_send.append(self.packet_buffer.popleft())
                
                if packets_to_send:
                    self._send_batch(packets_to_send)
                else:
                    time.sleep(0.1)
                    
            except Exception as e:
                self.errors += 1
                time.sleep(0.5)
    
    def _send_batch(self, packets: list):
        """Отправка пакета пакетов в API"""
        try:
            if len(packets) == 1:
                # Один пакет
                response = requests.post(
                    f"{self.api_url}/api/packet",
                    json=packets[0],
                    timeout=1
                )
            else:
                # Батч
                response = requests.post(
                    f"{self.api_url}/api/packets",
                    json={"packets": packets},
                    timeout=2
                )
            
            if response.status_code == 200:
                self.packets_sent += len(packets)
            else:
                self.errors += 1
                
        except requests.exceptions.RequestException:
            self.errors += 1
    
    def _print_status(self):
        """Печать текущего статуса"""
        elapsed = time.time() - self.start_time
        pps = self.packets_captured / max(elapsed, 1)
        
        print(f"\r[{elapsed:6.0f}s] Captured: {self.packets_captured:6d} | "
              f"Sent: {self.packets_sent:6d} | "
              f"Errors: {self.errors:3d} | "
              f"PPS: {pps:5.1f}", end="", flush=True)
    
    def _print_stats(self):
        """Печать финальной статистики"""
        elapsed = time.time() - self.start_time
        
        print(f"Duration:     {elapsed:.1f} seconds")
        print(f"Captured:     {self.packets_captured} packets")
        print(f"Sent to API:  {self.packets_sent} packets")
        print(f"Errors:       {self.errors}")
        print(f"Avg PPS:      {self.packets_captured / max(elapsed, 1):.1f}")


def main():
    parser = argparse.ArgumentParser(
        description="Packet Bridge - передача пакетов в Behavioral модуль"
    )
    parser.add_argument(
        "interface",
        nargs="?",
        default="enp0s8",
        help="Сетевой интерфейс для захвата (default: enp0s8)"
    )
    parser.add_argument(
        "--api",
        default="http://localhost:8081",
        help="URL Behavioral API (default: http://localhost:8081)"
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=10,
        help="Размер батча для отправки (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Проверка прав
    import os
    if os.geteuid() != 0:
        print("ОШИБКА: Требуются права root для захвата пакетов")
        print("Запустите: sudo python3 packet_bridge.py")
        sys.exit(1)
    
    bridge = PacketBridge(
        interface=args.interface,
        api_url=args.api,
        batch_size=args.batch
    )
    
    # Обработка Ctrl+C
    def signal_handler(sig, frame):
        bridge.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    bridge.start()


if __name__ == "__main__":
    main()
