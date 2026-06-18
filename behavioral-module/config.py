"""
Конфигурация модуля поведенческого анализа
"""

from dataclasses import dataclass, field
from typing import Dict, List
import json
import os


@dataclass
class BehavioralConfig:
    """Конфигурация поведенческого анализатора"""
    
    # Сервер
    api_host: str = "0.0.0.0"
    api_port: int = 8081
    
    # Временные окна для агрегации (секунды)
    time_window: int = 60          # Основное окно анализа
    short_window: int = 10         # Короткое окно для burst detection
    
    # Пороги для статистических детекторов
    zscore_threshold: float = 3.0           # Z-score > 3 = аномалия
    entropy_low_threshold: float = 1.0      # Слишком низкая энтропия
    entropy_high_threshold: float = 7.5     # Слишком высокая энтропия
    
    # Пороги rate-based
    packets_per_sec_threshold: int = 100    # Пакетов/сек от одного IP
    unique_ports_threshold: int = 20        # Уникальных портов за окно (port scan)
    unique_ips_threshold: int = 50          # Уникальных IP назначения (reconnaissance)
    
    # Isolation Forest параметры
    contamination: float = 0.05             # Ожидаемая доля аномалий (5%)
    n_estimators: int = 100                 # Количество деревьев
    max_samples: int = 256                  # Сэмплов на дерево
    
    # Веса для Score Fusion
    weight_signature: float = 1.0           # Вес сигнатурного анализа
    weight_statistical: float = 0.3         # Вес статистического анализа
    weight_ml: float = 0.7                  # Вес ML анализа
    
    # Финальный порог для алерта
    alert_threshold: float = 0.6
    
    # Пути к файлам
    model_path: str = "models/isolation_forest.joblib"
    training_data_path: str = "data/training_data.csv"
    
    # Go Engine
    go_engine_url: str = "http://localhost:8080"
    
    # Логирование
    log_level: str = "INFO"
    log_file: str = "behavioral.log"
    
    def to_dict(self) -> Dict:
        """Конвертация в словарь"""
        return {
            "api_host": self.api_host,
            "api_port": self.api_port,
            "time_window": self.time_window,
            "short_window": self.short_window,
            "zscore_threshold": self.zscore_threshold,
            "entropy_low_threshold": self.entropy_low_threshold,
            "entropy_high_threshold": self.entropy_high_threshold,
            "packets_per_sec_threshold": self.packets_per_sec_threshold,
            "unique_ports_threshold": self.unique_ports_threshold,
            "unique_ips_threshold": self.unique_ips_threshold,
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "weight_signature": self.weight_signature,
            "weight_statistical": self.weight_statistical,
            "weight_ml": self.weight_ml,
            "alert_threshold": self.alert_threshold,
            "model_path": self.model_path,
            "go_engine_url": self.go_engine_url,
            "log_level": self.log_level,
        }
    
    @classmethod
    def from_file(cls, path: str) -> "BehavioralConfig":
        """Загрузка из JSON файла"""
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
                return cls(**{k: v for k, v in data.items() 
                            if k in cls.__dataclass_fields__})
        return cls()
    
    def save(self, path: str):
        """Сохранение в JSON файл"""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Глобальная конфигурация
config = BehavioralConfig()
