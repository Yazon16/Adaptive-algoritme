"""
ML Model - Isolation Forest для обнаружения аномалий

Isolation Forest идеально подходит для:
- Unsupervised learning (не нужны метки)
- Быстрое обучение и inference
- Хорошо работает с высокоразмерными данными
"""

import os
import time
import threading
import pickle
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not installed. ML features disabled.")

from feature_extractor import FlowFeatures
from config import BehavioralConfig, config


@dataclass
class MLResult:
    """Результат ML анализа"""
    src_ip: str
    timestamp: float
    
    # Anomaly score от Isolation Forest (-1 to 1, где -1 = аномалия)
    raw_score: float = 0.0
    
    # Нормализованный скор (0.0 - 1.0, где 1.0 = аномалия)
    anomaly_score: float = 0.0
    
    # Предсказание (-1 = аномалия, 1 = норма)
    prediction: int = 1
    
    # Признаки использованные для предсказания
    features_used: List[float] = None
    
    def __post_init__(self):
        if self.features_used is None:
            self.features_used = []
    
    def to_dict(self) -> Dict:
        return {
            "src_ip": self.src_ip,
            "timestamp": float(self.timestamp),
            "raw_score": float(round(self.raw_score, 4)),
            "anomaly_score": float(round(self.anomaly_score, 4)),
            "prediction": int(self.prediction),
            "is_anomaly": bool(self.prediction == -1),
        }


class IsolationForestModel:
    """
    Обёртка над Isolation Forest для обнаружения сетевых аномалий
    """
    
    def __init__(self, config: BehavioralConfig = None):
        self.config = config or BehavioralConfig()
        
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn is required for ML features")
        
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False
        self.training_samples = 0
        self.lock = threading.Lock()
        
        # Статистика
        self.total_predictions = 0
        self.anomalies_detected = 0
        self.start_time = time.time()
        
        # Буфер для онлайн-обучения
        self.training_buffer: List[List[float]] = []
        self.buffer_size = 1000
    
    def _create_model(self) -> IsolationForest:
        """Создание модели с параметрами из конфига"""
        return IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            contamination=self.config.contamination,
            random_state=42,
            n_jobs=-1,  # Использовать все ядра
        )
    
    def train(self, features_list: List[FlowFeatures]) -> Dict:
        """
        Обучение модели на списке признаков
        
        Args:
            features_list: Список FlowFeatures от нормального трафика
            
        Returns:
            Dict со статистикой обучения
        """
        if len(features_list) < 10:
            return {"error": "Need at least 10 samples for training"}
        
        with self.lock:
            # Преобразование в матрицу
            X = np.array([f.to_vector() for f in features_list])
            
            # Нормализация
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Обучение
            self.model = self._create_model()
            self.model.fit(X_scaled)
            
            self.is_trained = True
            self.training_samples = len(features_list)
            
            return {
                "status": "trained",
                "samples": self.training_samples,
                "features": len(FlowFeatures.feature_names()),
                "contamination": self.config.contamination,
            }
    
    def train_from_vectors(self, vectors: List[List[float]]) -> Dict:
        """Обучение на сырых векторах признаков"""
        if len(vectors) < 10:
            return {"error": "Need at least 10 samples for training"}
        
        with self.lock:
            X = np.array(vectors)
            
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            self.model = self._create_model()
            self.model.fit(X_scaled)
            
            self.is_trained = True
            self.training_samples = len(vectors)
            
            return {
                "status": "trained",
                "samples": self.training_samples,
            }
    
    def add_to_buffer(self, features: FlowFeatures):
        """Добавление в буфер для онлайн-обучения"""
        with self.lock:
            self.training_buffer.append(features.to_vector())
            
            # Ограничение размера буфера
            if len(self.training_buffer) > self.buffer_size:
                self.training_buffer = self.training_buffer[-self.buffer_size:]
    
    def retrain_from_buffer(self) -> Dict:
        """Переобучение на данных из буфера"""
        with self.lock:
            if len(self.training_buffer) < 50:
                return {"error": f"Need at least 50 samples, have {len(self.training_buffer)}"}
            
            return self.train_from_vectors(self.training_buffer)
    
    def predict(self, features: FlowFeatures) -> MLResult:
        """
        Предсказание для одного набора признаков
        
        Returns:
            MLResult с оценкой аномальности
        """
        result = MLResult(
            src_ip=features.src_ip,
            timestamp=time.time()
        )
        
        if not self.is_trained:
            result.anomaly_score = 0.5  # Неопределённость если модель не обучена
            return result
        
        with self.lock:
            self.total_predictions += 1
            
            # Преобразование признаков
            X = np.array([features.to_vector()])
            result.features_used = features.to_vector()
            
            # Нормализация
            X_scaled = self.scaler.transform(X)
            
            # Предсказание
            prediction = self.model.predict(X_scaled)[0]
            raw_score = self.model.decision_function(X_scaled)[0]
            
            result.prediction = int(prediction)
            result.raw_score = float(raw_score)
            
            # Нормализация скора в 0-1
            # decision_function возвращает значения примерно от -0.5 до 0.5
            # Отрицательные = аномалии
            result.anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
            
            if result.prediction == -1:
                self.anomalies_detected += 1
            
            return result
    
    def predict_batch(self, features_list: List[FlowFeatures]) -> List[MLResult]:
        """Пакетное предсказание"""
        return [self.predict(f) for f in features_list]
    
    def save(self, path: str = None) -> bool:
        """Сохранение модели"""
        if not self.is_trained:
            return False
        
        path = path or self.config.model_path
        
        with self.lock:
            data = {
                "model": self.model,
                "scaler": self.scaler,
                "training_samples": self.training_samples,
                "config": self.config.to_dict(),
            }
            
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
            joblib.dump(data, path)
            
            return True
    
    def load(self, path: str = None) -> bool:
        """Загрузка модели"""
        path = path or self.config.model_path
        
        if not os.path.exists(path):
            return False
        
        with self.lock:
            data = joblib.load(path)
            
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.training_samples = data.get("training_samples", 0)
            self.is_trained = True
            
            return True
    
    def get_stats(self) -> Dict:
        """Статистика модели"""
        uptime = time.time() - self.start_time
        return {
            "is_trained": bool(self.is_trained),
            "training_samples": int(self.training_samples),
            "total_predictions": int(self.total_predictions),
            "anomalies_detected": int(self.anomalies_detected),
            "anomaly_rate": float(round(self.anomalies_detected / max(self.total_predictions, 1), 4)),
            "buffer_size": int(len(self.training_buffer)),
            "uptime_seconds": float(round(uptime, 2)),
        }


# Глобальная модель
_model: Optional[IsolationForestModel] = None


def get_model() -> IsolationForestModel:
    """Получение глобальной модели"""
    global _model
    if _model is None:
        _model = IsolationForestModel()
    return _model


if __name__ == "__main__":
    import random
    from feature_extractor import FeatureExtractor, PacketInfo
    
    if not SKLEARN_AVAILABLE:
        print("scikit-learn not available, skipping test")
        exit(1)
    
    print("=== Тест Isolation Forest модели ===\n")
    
    extractor = FeatureExtractor(window_sec=10)
    model = IsolationForestModel()
    
    # Генерация нормального трафика
    print("Генерация нормального трафика...")
    normal_features = []
    
    for ip_suffix in range(1, 21):  # 20 разных IP
        src_ip = f"192.168.1.{ip_suffix}"
        
        for _ in range(50):  # 50 пакетов от каждого
            packet = PacketInfo(
                timestamp=time.time() + random.random(),
                src_ip=src_ip,
                dst_ip="10.0.0.1",
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443]),
                protocol="TCP",
                size=random.randint(200, 800),
                tcp_flags=0x10,  # ACK
            )
            extractor.process_packet(packet)
        
        features = extractor.get_features(src_ip)
        if features:
            normal_features.append(features)
    
    print(f"Собрано {len(normal_features)} наборов признаков\n")
    
    # Обучение
    print("Обучение модели...")
    result = model.train(normal_features)
    print(f"Результат: {result}\n")
    
    # Тест на нормальном трафике
    print("Тест на нормальном трафике:")
    for features in normal_features[:3]:
        ml_result = model.predict(features)
        print(f"  {features.src_ip}: score={ml_result.anomaly_score:.3f}, anomaly={ml_result.prediction == -1}")
    
    # Генерация аномального трафика (port scan)
    print("\nГенерация аномального трафика (port scan)...")
    for i in range(100):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="10.10.10.10",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=1000 + i,  # Разные порты
            protocol="TCP",
            size=64,
            tcp_flags=0x02,  # SYN
        )
        extractor.process_packet(packet)
    
    anomaly_features = extractor.get_features("10.10.10.10")
    if anomaly_features:
        ml_result = model.predict(anomaly_features)
        print(f"\nАномальный IP 10.10.10.10:")
        print(f"  Anomaly score: {ml_result.anomaly_score:.3f}")
        print(f"  Raw score: {ml_result.raw_score:.3f}")
        print(f"  Is anomaly: {ml_result.prediction == -1}")
    
    # Сохранение модели
    print("\nСохранение модели...")
    model.save("models/test_model.joblib")
    print("Модель сохранена")
    
    print(f"\nСтатистика: {model.get_stats()}")
