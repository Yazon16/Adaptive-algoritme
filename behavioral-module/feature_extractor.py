"""
Feature Extractor - Извлечение признаков из сетевого трафика

Извлекает статистические признаки для поведенческого анализа:
- Частотные характеристики (packets/sec, bytes/sec)
- Распределения (порты, IP)
- Энтропия payload
- Временные паттерны
"""

import math
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import statistics


@dataclass
class PacketInfo:
    """Информация о пакете"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    payload: bytes = b""
    tcp_flags: int = 0


@dataclass 
class FlowFeatures:
    """Признаки потока трафика от одного IP"""
    src_ip: str
    timestamp: float
    
    # Частотные признаки
    packet_count: int = 0
    byte_count: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    
    # Размеры пакетов
    avg_packet_size: float = 0.0
    std_packet_size: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0
    
    # Распределение портов
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    dst_port_entropy: float = 0.0
    
    # TCP флаги
    syn_count: int = 0
    syn_ratio: float = 0.0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    
    # Временные характеристики
    avg_inter_arrival: float = 0.0
    std_inter_arrival: float = 0.0
    
    # Payload характеристики
    avg_payload_entropy: float = 0.0
    empty_payload_ratio: float = 0.0
    
    def to_vector(self) -> List[float]:
        """Преобразование в вектор для ML модели"""
        return [
            self.packets_per_sec,
            self.bytes_per_sec,
            self.avg_packet_size,
            self.std_packet_size,
            float(self.unique_dst_ports),
            float(self.unique_dst_ips),
            self.dst_port_entropy,
            self.syn_ratio,
            self.avg_inter_arrival,
            self.std_inter_arrival,
            self.avg_payload_entropy,
            self.empty_payload_ratio,
        ]
    
    @staticmethod
    def feature_names() -> List[str]:
        """Имена признаков"""
        return [
            "packets_per_sec",
            "bytes_per_sec", 
            "avg_packet_size",
            "std_packet_size",
            "unique_dst_ports",
            "unique_dst_ips",
            "dst_port_entropy",
            "syn_ratio",
            "avg_inter_arrival",
            "std_inter_arrival",
            "avg_payload_entropy",
            "empty_payload_ratio",
        ]
    
    def to_dict(self) -> Dict:
        """Преобразование в словарь"""
        return {
            "src_ip": self.src_ip,
            "timestamp": self.timestamp,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packets_per_sec": round(self.packets_per_sec, 2),
            "bytes_per_sec": round(self.bytes_per_sec, 2),
            "avg_packet_size": round(self.avg_packet_size, 2),
            "std_packet_size": round(self.std_packet_size, 2),
            "unique_dst_ports": self.unique_dst_ports,
            "unique_dst_ips": self.unique_dst_ips,
            "dst_port_entropy": round(self.dst_port_entropy, 4),
            "syn_ratio": round(self.syn_ratio, 4),
            "avg_inter_arrival": round(self.avg_inter_arrival, 4),
            "std_inter_arrival": round(self.std_inter_arrival, 4),
            "avg_payload_entropy": round(self.avg_payload_entropy, 4),
            "empty_payload_ratio": round(self.empty_payload_ratio, 4),
        }


class IPFlowTracker:
    """Отслеживание потока пакетов от одного IP"""
    
    def __init__(self, src_ip: str, window_sec: int = 60):
        self.src_ip = src_ip
        self.window_sec = window_sec
        self.packets: List[PacketInfo] = []
        self.lock = threading.Lock()
    
    def add_packet(self, packet: PacketInfo):
        """Добавление пакета"""
        with self.lock:
            self.packets.append(packet)
            self._cleanup_old_packets()
    
    def _cleanup_old_packets(self):
        """Удаление старых пакетов за пределами окна"""
        cutoff = time.time() - self.window_sec
        self.packets = [p for p in self.packets if p.timestamp >= cutoff]
    
    def get_features(self) -> FlowFeatures:
        """Извлечение признаков из текущего окна"""
        with self.lock:
            self._cleanup_old_packets()
            
            if not self.packets:
                return FlowFeatures(src_ip=self.src_ip, timestamp=time.time())
            
            features = FlowFeatures(
                src_ip=self.src_ip,
                timestamp=time.time()
            )
            
            # Базовые счётчики
            features.packet_count = len(self.packets)
            features.byte_count = sum(p.size for p in self.packets)
            
            # Временной диапазон
            timestamps = [p.timestamp for p in self.packets]
            time_span = max(timestamps) - min(timestamps)
            if time_span < 0.001:
                time_span = 1.0  # Избегаем деления на 0
            
            # Частотные признаки
            features.packets_per_sec = features.packet_count / time_span
            features.bytes_per_sec = features.byte_count / time_span
            
            # Размеры пакетов
            sizes = [p.size for p in self.packets]
            features.avg_packet_size = statistics.mean(sizes)
            features.std_packet_size = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
            features.min_packet_size = min(sizes)
            features.max_packet_size = max(sizes)
            
            # Распределение портов и IP
            dst_ports = [p.dst_port for p in self.packets]
            dst_ips = [p.dst_ip for p in self.packets]
            features.unique_dst_ports = len(set(dst_ports))
            features.unique_dst_ips = len(set(dst_ips))
            features.dst_port_entropy = self._calculate_entropy(dst_ports)
            
            # TCP флаги
            features.syn_count = sum(1 for p in self.packets if p.tcp_flags & 0x02)
            features.ack_count = sum(1 for p in self.packets if p.tcp_flags & 0x10)
            features.rst_count = sum(1 for p in self.packets if p.tcp_flags & 0x04)
            features.fin_count = sum(1 for p in self.packets if p.tcp_flags & 0x01)
            features.syn_ratio = features.syn_count / features.packet_count
            
            # Inter-arrival time
            if len(timestamps) > 1:
                sorted_ts = sorted(timestamps)
                inter_arrivals = [sorted_ts[i+1] - sorted_ts[i] 
                                 for i in range(len(sorted_ts)-1)]
                features.avg_inter_arrival = statistics.mean(inter_arrivals)
                features.std_inter_arrival = statistics.stdev(inter_arrivals) if len(inter_arrivals) > 1 else 0.0
            
            # Payload entropy
            payloads = [p.payload for p in self.packets if p.payload]
            if payloads:
                entropies = [self._calculate_byte_entropy(p) for p in payloads]
                features.avg_payload_entropy = statistics.mean(entropies)
            features.empty_payload_ratio = 1.0 - (len(payloads) / features.packet_count)
            
            return features
    
    @staticmethod
    def _calculate_entropy(values: List) -> float:
        """Расчёт энтропии Шеннона для списка значений"""
        if not values:
            return 0.0
        
        freq = defaultdict(int)
        for v in values:
            freq[v] += 1
        
        total = len(values)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def _calculate_byte_entropy(data: bytes) -> float:
        """Расчёт энтропии для байтовых данных"""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        total = len(data)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy


class FeatureExtractor:
    """
    Главный класс извлечения признаков
    
    Отслеживает все IP-адреса и извлекает признаки для каждого
    """
    
    def __init__(self, window_sec: int = 60, max_tracked_ips: int = 10000):
        self.window_sec = window_sec
        self.max_tracked_ips = max_tracked_ips
        self.ip_trackers: Dict[str, IPFlowTracker] = {}
        self.lock = threading.Lock()
        
        # Статистика
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
    
    def process_packet(self, packet: PacketInfo):
        """Обработка входящего пакета"""
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet.size
            
            # Получение или создание трекера для IP
            if packet.src_ip not in self.ip_trackers:
                # Проверка лимита
                if len(self.ip_trackers) >= self.max_tracked_ips:
                    self._evict_oldest_tracker()
                
                self.ip_trackers[packet.src_ip] = IPFlowTracker(
                    packet.src_ip, 
                    self.window_sec
                )
            
            self.ip_trackers[packet.src_ip].add_packet(packet)
    
    def process_packet_dict(self, packet_data: Dict):
        """Обработка пакета из словаря (для API)"""
        packet = PacketInfo(
            timestamp=packet_data.get("timestamp", time.time()),
            src_ip=packet_data.get("src_ip", "0.0.0.0"),
            dst_ip=packet_data.get("dst_ip", "0.0.0.0"),
            src_port=packet_data.get("src_port", 0),
            dst_port=packet_data.get("dst_port", 0),
            protocol=packet_data.get("protocol", "TCP"),
            size=packet_data.get("size", 0),
            payload=packet_data.get("payload", b"").encode() if isinstance(packet_data.get("payload"), str) else packet_data.get("payload", b""),
            tcp_flags=packet_data.get("tcp_flags", 0),
        )
        self.process_packet(packet)
    
    def get_features(self, src_ip: str) -> Optional[FlowFeatures]:
        """Получение признаков для конкретного IP"""
        with self.lock:
            if src_ip in self.ip_trackers:
                return self.ip_trackers[src_ip].get_features()
            return None
    
    def get_all_features(self) -> Dict[str, FlowFeatures]:
        """Получение признаков для всех отслеживаемых IP"""
        with self.lock:
            return {ip: tracker.get_features() 
                    for ip, tracker in self.ip_trackers.items()}
    
    def get_stats(self) -> Dict:
        """Статистика работы экстрактора"""
        uptime = time.time() - self.start_time
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "tracked_ips": len(self.ip_trackers),
            "uptime_seconds": round(uptime, 2),
            "packets_per_second": round(self.total_packets / max(uptime, 1), 2),
        }
    
    def _evict_oldest_tracker(self):
        """Удаление самого старого трекера при переполнении"""
        if not self.ip_trackers:
            return
        
        oldest_ip = None
        oldest_time = float('inf')
        
        for ip, tracker in self.ip_trackers.items():
            if tracker.packets:
                last_time = max(p.timestamp for p in tracker.packets)
                if last_time < oldest_time:
                    oldest_time = last_time
                    oldest_ip = ip
        
        if oldest_ip:
            del self.ip_trackers[oldest_ip]
    
    def cleanup(self):
        """Очистка неактивных трекеров"""
        with self.lock:
            cutoff = time.time() - self.window_sec * 2
            inactive = []
            
            for ip, tracker in self.ip_trackers.items():
                if not tracker.packets:
                    inactive.append(ip)
                elif max(p.timestamp for p in tracker.packets) < cutoff:
                    inactive.append(ip)
            
            for ip in inactive:
                del self.ip_trackers[ip]
            
            return len(inactive)


# Глобальный экстрактор
_extractor: Optional[FeatureExtractor] = None


def get_extractor(window_sec: int = 60) -> FeatureExtractor:
    """Получение глобального экстрактора"""
    global _extractor
    if _extractor is None:
        _extractor = FeatureExtractor(window_sec=window_sec)
    return _extractor


if __name__ == "__main__":
    # Тест
    extractor = FeatureExtractor(window_sec=10)
    
    # Симуляция пакетов
    for i in range(100):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 8080]),
            protocol="TCP",
            size=random.randint(64, 1500),
            tcp_flags=0x02 if random.random() < 0.3 else 0x10,
        )
        extractor.process_packet(packet)
    
    features = extractor.get_features("192.168.1.100")
    if features:
        print("Features extracted:")
        for k, v in features.to_dict().items():
            print(f"  {k}: {v}")
