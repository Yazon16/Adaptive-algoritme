"""
Statistical Analyzer - Статистические методы обнаружения аномалий

Реализует:
- Z-score детектирование
- Entropy-based детектирование
- Rate-based детектирование
- Комбинированный статистический скор
"""

import math
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import statistics

from feature_extractor import FlowFeatures
from config import BehavioralConfig, config


@dataclass
class StatisticalResult:
    """Результат статистического анализа"""
    src_ip: str
    timestamp: float
    
    # Итоговый скор (0.0 - 1.0)
    anomaly_score: float = 0.0
    
    # Отдельные компоненты
    zscore_anomaly: float = 0.0
    entropy_anomaly: float = 0.0
    rate_anomaly: float = 0.0
    port_scan_anomaly: float = 0.0
    
    # Детали
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict:
        # Безопасная конвертация details для JSON
        safe_details = {}
        if self.details:
            for k, v in self.details.items():
                if isinstance(v, dict):
                    safe_details[k] = {
                        k2: (float(v2) if hasattr(v2, 'item') else 
                             bool(v2) if isinstance(v2, (bool,)) else
                             float(v2) if isinstance(v2, (int, float)) else v2)
                        for k2, v2 in v.items()
                    }
                elif hasattr(v, 'item'):  # numpy type
                    safe_details[k] = float(v)
                elif isinstance(v, bool):
                    safe_details[k] = bool(v)
                elif isinstance(v, (int, float)):
                    safe_details[k] = float(v)
                else:
                    safe_details[k] = v
        
        return {
            "src_ip": self.src_ip,
            "timestamp": float(self.timestamp),
            "anomaly_score": float(round(self.anomaly_score, 4)),
            "zscore_anomaly": float(round(self.zscore_anomaly, 4)),
            "entropy_anomaly": float(round(self.entropy_anomaly, 4)),
            "rate_anomaly": float(round(self.rate_anomaly, 4)),
            "port_scan_anomaly": float(round(self.port_scan_anomaly, 4)),
            "details": safe_details,
        }


class BaselineTracker:
    """
    Отслеживание baseline (нормальных значений) для метрик
    
    Использует скользящее окно для расчёта среднего и стандартного отклонения
    """
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.values: deque = deque(maxlen=window_size)
        self.lock = threading.Lock()
        
        # Кэшированные значения
        self._mean: Optional[float] = None
        self._std: Optional[float] = None
        self._dirty = True
    
    def add(self, value: float):
        """Добавление значения"""
        with self.lock:
            self.values.append(value)
            self._dirty = True
    
    def get_stats(self) -> Tuple[float, float]:
        """Получение среднего и стандартного отклонения"""
        with self.lock:
            if self._dirty or self._mean is None:
                if len(self.values) < 2:
                    self._mean = sum(self.values) / len(self.values) if self.values else 0.0
                    self._std = 1.0  # Избегаем деления на 0
                else:
                    self._mean = statistics.mean(self.values)
                    self._std = statistics.stdev(self.values)
                    if self._std < 0.001:
                        self._std = 0.001  # Минимальное значение
                self._dirty = False
            
            return self._mean, self._std
    
    def calculate_zscore(self, value: float) -> float:
        """Расчёт Z-score для значения"""
        mean, std = self.get_stats()
        return abs(value - mean) / std
    
    def is_ready(self) -> bool:
        """Достаточно ли данных для анализа"""
        return len(self.values) >= 10


class StatisticalAnalyzer:
    """
    Статистический анализатор аномалий
    
    Комбинирует несколько методов:
    1. Z-score - отклонение от среднего
    2. Entropy - необычность распределения
    3. Rate - превышение порогов частоты
    4. Port scan - сканирование портов
    """
    
    def __init__(self, config: BehavioralConfig = None):
        self.config = config or BehavioralConfig()
        
        # Baseline трекеры для разных метрик
        self.baselines: Dict[str, BaselineTracker] = {
            "packets_per_sec": BaselineTracker(),
            "bytes_per_sec": BaselineTracker(),
            "avg_packet_size": BaselineTracker(),
            "unique_dst_ports": BaselineTracker(),
            "unique_dst_ips": BaselineTracker(),
            "syn_ratio": BaselineTracker(),
            "avg_inter_arrival": BaselineTracker(),
            "payload_entropy": BaselineTracker(),
        }
        
        # Статистика
        self.total_analyzed = 0
        self.anomalies_detected = 0
        self.start_time = time.time()
        
        self.lock = threading.Lock()
    
    def update_baseline(self, features: FlowFeatures):
        """Обновление baseline нормальными значениями"""
        with self.lock:
            self.baselines["packets_per_sec"].add(features.packets_per_sec)
            self.baselines["bytes_per_sec"].add(features.bytes_per_sec)
            self.baselines["avg_packet_size"].add(features.avg_packet_size)
            self.baselines["unique_dst_ports"].add(float(features.unique_dst_ports))
            self.baselines["unique_dst_ips"].add(float(features.unique_dst_ips))
            self.baselines["syn_ratio"].add(features.syn_ratio)
            self.baselines["avg_inter_arrival"].add(features.avg_inter_arrival)
            self.baselines["payload_entropy"].add(features.avg_payload_entropy)
    
    def analyze(self, features: FlowFeatures) -> StatisticalResult:
        """
        Анализ признаков на аномальность
        
        Returns:
            StatisticalResult с оценками аномальности
        """
        self.total_analyzed += 1
        
        result = StatisticalResult(
            src_ip=features.src_ip,
            timestamp=time.time()
        )
        
        details = {}
        
        # 1. Z-score анализ
        zscore_anomaly, zscore_details = self._analyze_zscore(features)
        result.zscore_anomaly = zscore_anomaly
        details["zscore"] = zscore_details
        
        # 2. Entropy анализ
        entropy_anomaly, entropy_details = self._analyze_entropy(features)
        result.entropy_anomaly = entropy_anomaly
        details["entropy"] = entropy_details
        
        # 3. Rate-based анализ
        rate_anomaly, rate_details = self._analyze_rate(features)
        result.rate_anomaly = rate_anomaly
        details["rate"] = rate_details
        
        # 4. Port scan детектирование
        portscan_anomaly, portscan_details = self._analyze_portscan(features)
        result.port_scan_anomaly = portscan_anomaly
        details["portscan"] = portscan_details
        
        # Комбинированный скор (взвешенное среднее)
        result.anomaly_score = self._combine_scores(
            zscore_anomaly,
            entropy_anomaly,
            rate_anomaly,
            portscan_anomaly
        )
        
        result.details = details
        
        if result.anomaly_score > self.config.alert_threshold:
            self.anomalies_detected += 1
        
        return result
    
    def _analyze_zscore(self, features: FlowFeatures) -> Tuple[float, Dict]:
        """Z-score анализ - отклонение от нормы"""
        details = {}
        max_zscore = 0.0
        
        metrics = [
            ("packets_per_sec", features.packets_per_sec),
            ("bytes_per_sec", features.bytes_per_sec),
            ("avg_packet_size", features.avg_packet_size),
            ("syn_ratio", features.syn_ratio),
        ]
        
        for name, value in metrics:
            if self.baselines[name].is_ready():
                zscore = self.baselines[name].calculate_zscore(value)
                details[name] = round(zscore, 2)
                max_zscore = max(max_zscore, zscore)
        
        # Нормализация в 0-1
        anomaly = min(1.0, max_zscore / (self.config.zscore_threshold * 2))
        
        return anomaly, details
    
    def _analyze_entropy(self, features: FlowFeatures) -> Tuple[float, Dict]:
        """Entropy анализ - необычность распределения"""
        details = {}
        anomaly = 0.0
        
        # Проверка энтропии payload
        payload_entropy = features.avg_payload_entropy
        details["payload_entropy"] = round(payload_entropy, 4)
        
        if payload_entropy < self.config.entropy_low_threshold:
            # Слишком низкая энтропия (повторяющиеся данные)
            anomaly = max(anomaly, 0.5)
            details["low_entropy_flag"] = True
        elif payload_entropy > self.config.entropy_high_threshold:
            # Слишком высокая энтропия (зашифрованные/случайные данные)
            anomaly = max(anomaly, 0.6)
            details["high_entropy_flag"] = True
        
        # Проверка энтропии портов
        port_entropy = features.dst_port_entropy
        details["port_entropy"] = round(port_entropy, 4)
        
        if port_entropy > 4.0 and features.unique_dst_ports > 10:
            # Высокая энтропия портов + много уникальных = подозрительно
            anomaly = max(anomaly, 0.7)
            details["high_port_entropy_flag"] = True
        
        return anomaly, details
    
    def _analyze_rate(self, features: FlowFeatures) -> Tuple[float, Dict]:
        """Rate-based анализ - превышение порогов"""
        details = {}
        anomaly = 0.0
        
        # Packets per second
        pps = features.packets_per_sec
        pps_threshold = self.config.packets_per_sec_threshold
        details["packets_per_sec"] = round(pps, 2)
        details["pps_threshold"] = pps_threshold
        
        if pps > pps_threshold:
            pps_anomaly = min(1.0, pps / (pps_threshold * 2))
            anomaly = max(anomaly, pps_anomaly)
            details["pps_exceeded"] = True
        
        # SYN ratio (потенциальный SYN flood)
        syn_ratio = features.syn_ratio
        details["syn_ratio"] = round(syn_ratio, 4)
        
        if syn_ratio > 0.8 and features.packet_count > 50:
            # Очень высокий процент SYN пакетов
            anomaly = max(anomaly, 0.9)
            details["syn_flood_flag"] = True
        elif syn_ratio > 0.5 and features.packet_count > 30:
            anomaly = max(anomaly, 0.6)
            details["high_syn_ratio_flag"] = True
        
        return anomaly, details
    
    def _analyze_portscan(self, features: FlowFeatures) -> Tuple[float, Dict]:
        """Детектирование сканирования портов"""
        details = {}
        anomaly = 0.0
        
        unique_ports = features.unique_dst_ports
        unique_ips = features.unique_dst_ips
        packet_count = features.packet_count
        
        details["unique_dst_ports"] = unique_ports
        details["unique_dst_ips"] = unique_ips
        
        # Вертикальный скан (много портов на одном IP)
        if unique_ports > self.config.unique_ports_threshold:
            port_ratio = unique_ports / max(packet_count, 1)
            if port_ratio > 0.5:  # Много уникальных портов относительно пакетов
                anomaly = max(anomaly, 0.85)
                details["vertical_scan_flag"] = True
        
        # Горизонтальный скан (один порт на много IP)
        if unique_ips > self.config.unique_ips_threshold:
            anomaly = max(anomaly, 0.8)
            details["horizontal_scan_flag"] = True
        
        # Комбинированный (много портов И много IP)
        if unique_ports > 10 and unique_ips > 10:
            anomaly = max(anomaly, 0.9)
            details["combined_scan_flag"] = True
        
        return anomaly, details
    
    def _combine_scores(self, zscore: float, entropy: float, 
                        rate: float, portscan: float) -> float:
        """Комбинирование отдельных скоров в итоговый"""
        # Веса для разных типов аномалий
        weights = {
            "zscore": 0.2,
            "entropy": 0.2,
            "rate": 0.3,
            "portscan": 0.3,
        }
        
        weighted_sum = (
            weights["zscore"] * zscore +
            weights["entropy"] * entropy +
            weights["rate"] * rate +
            weights["portscan"] * portscan
        )
        
        # Усиление при множественных аномалиях
        anomaly_count = sum(1 for s in [zscore, entropy, rate, portscan] if s > 0.5)
        if anomaly_count >= 3:
            weighted_sum = min(1.0, weighted_sum * 1.3)
        elif anomaly_count >= 2:
            weighted_sum = min(1.0, weighted_sum * 1.15)
        
        return min(1.0, weighted_sum)
    
    def get_stats(self) -> Dict:
        """Статистика анализатора"""
        uptime = time.time() - self.start_time
        return {
            "total_analyzed": int(self.total_analyzed),
            "anomalies_detected": int(self.anomalies_detected),
            "anomaly_rate": float(round(self.anomalies_detected / max(self.total_analyzed, 1), 4)),
            "uptime_seconds": float(round(uptime, 2)),
            "baselines_ready": {
                name: bool(tracker.is_ready()) 
                for name, tracker in self.baselines.items()
            },
        }
    
    def is_baseline_ready(self) -> bool:
        """Готов ли baseline для анализа"""
        return all(tracker.is_ready() for tracker in self.baselines.values())


# Глобальный анализатор
_analyzer: Optional[StatisticalAnalyzer] = None


def get_analyzer() -> StatisticalAnalyzer:
    """Получение глобального анализатора"""
    global _analyzer
    if _analyzer is None:
        _analyzer = StatisticalAnalyzer()
    return _analyzer


if __name__ == "__main__":
    # Тест
    import random
    from feature_extractor import FeatureExtractor, PacketInfo
    
    extractor = FeatureExtractor(window_sec=10)
    analyzer = StatisticalAnalyzer()
    
    print("Генерация нормального трафика для baseline...")
    
    # Нормальный трафик
    for i in range(200):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443]),
            protocol="TCP",
            size=random.randint(200, 800),
            tcp_flags=0x10,  # ACK
        )
        extractor.process_packet(packet)
        
        if i % 20 == 0:
            features = extractor.get_features("192.168.1.100")
            if features:
                analyzer.update_baseline(features)
    
    print(f"Baseline ready: {analyzer.is_baseline_ready()}")
    
    # Аномальный трафик (port scan)
    print("\nГенерация аномального трафика (port scan)...")
    for i in range(50):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.200",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=1000 + i,  # Разные порты
            protocol="TCP",
            size=64,
            tcp_flags=0x02,  # SYN
        )
        extractor.process_packet(packet)
    
    features = extractor.get_features("192.168.1.200")
    if features:
        result = analyzer.analyze(features)
        print(f"\nРезультат анализа аномального IP:")
        for k, v in result.to_dict().items():
            print(f"  {k}: {v}")
