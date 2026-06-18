"""
Score Fusion - Объединение результатов всех анализаторов

Комбинирует:
- Сигнатурный анализ (от Go-движка)
- Статистический анализ
- ML анализ (Isolation Forest)
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import logging

from config import BehavioralConfig, config


@dataclass
class ThreatAssessment:
    """Итоговая оценка угрозы"""
    src_ip: str
    timestamp: float
    
    # Итоговый скор (0.0 - 1.0)
    final_score: float = 0.0
    
    # Решение
    is_threat: bool = False
    threat_level: str = "none"  # none, low, medium, high, critical
    
    # Компоненты
    signature_score: float = 0.0
    statistical_score: float = 0.0
    ml_score: float = 0.0
    
    # Детали от каждого анализатора
    signature_details: Dict = field(default_factory=dict)
    statistical_details: Dict = field(default_factory=dict)
    ml_details: Dict = field(default_factory=dict)
    
    # Рекомендуемое действие
    recommended_action: str = "none"  # none, monitor, alert, block
    
    def to_dict(self) -> Dict:
        return {
            "src_ip": str(self.src_ip),
            "timestamp": float(self.timestamp),
            "final_score": float(round(self.final_score, 4)),
            "is_threat": bool(self.is_threat),
            "threat_level": str(self.threat_level),
            "recommended_action": str(self.recommended_action),
            "components": {
                "signature": float(round(self.signature_score, 4)),
                "statistical": float(round(self.statistical_score, 4)),
                "ml": float(round(self.ml_score, 4)),
            },
            "details": {
                "signature": self.signature_details or {},
                "statistical": self.statistical_details or {},
                "ml": self.ml_details or {},
            },
        }


class ScoreFusion:
    """
    Объединение результатов от разных анализаторов
    
    Стратегии:
    1. Weighted Average - взвешенное среднее
    2. Maximum - максимум из всех
    3. Voting - голосование
    4. Cascade - каскадная проверка
    """
    
    def __init__(self, config: BehavioralConfig = None):
        self.config = config or BehavioralConfig()
        self.logger = logging.getLogger("ScoreFusion")
        
        # Статистика
        self.total_assessments = 0
        self.threats_detected = 0
        self.start_time = time.time()
    
    def assess(self,
               src_ip: str,
               signature_score: float = 0.0,
               signature_details: Dict = None,
               statistical_score: float = 0.0,
               statistical_details: Dict = None,
               ml_score: float = 0.0,
               ml_details: Dict = None) -> ThreatAssessment:
        """
        Создание итоговой оценки угрозы
        
        Args:
            src_ip: IP источника
            signature_score: Скор от сигнатурного анализа (0 или 1)
            statistical_score: Скор от статистического анализа (0.0-1.0)
            ml_score: Скор от ML модели (0.0-1.0)
            *_details: Детали от каждого анализатора
            
        Returns:
            ThreatAssessment с итоговой оценкой
        """
        self.total_assessments += 1
        
        assessment = ThreatAssessment(
            src_ip=src_ip,
            timestamp=time.time(),
            signature_score=signature_score,
            statistical_score=statistical_score,
            ml_score=ml_score,
            signature_details=signature_details or {},
            statistical_details=statistical_details or {},
            ml_details=ml_details or {},
        )
        
        # Расчёт итогового скора
        assessment.final_score = self._calculate_final_score(
            signature_score,
            statistical_score,
            ml_score
        )
        
        # Определение уровня угрозы
        assessment.threat_level = self._determine_threat_level(assessment.final_score)
        assessment.is_threat = assessment.final_score >= self.config.alert_threshold
        
        # Рекомендуемое действие
        assessment.recommended_action = self._recommend_action(assessment)
        
        if assessment.is_threat:
            self.threats_detected += 1
        
        return assessment
    
    def _calculate_final_score(self,
                               signature_score: float,
                               statistical_score: float,
                               ml_score: float) -> float:
        """
        Расчёт итогового скора
        
        Логика:
        - Если сигнатура сработала (score=1) - сразу высокий приоритет
        - Иначе комбинация statistical + ML с весами
        - Усиление при согласованности
        """
        
        # Если сигнатура сработала - это точное совпадение
        if signature_score >= 1.0:
            return 1.0
        
        # Комбинация behavioral анализов
        w_stat = self.config.weight_statistical
        w_ml = self.config.weight_ml
        
        # Нормализация весов
        total_weight = w_stat + w_ml
        w_stat /= total_weight
        w_ml /= total_weight
        
        combined = w_stat * statistical_score + w_ml * ml_score
        
        # Усиление при согласованности обоих методов
        if statistical_score > 0.5 and ml_score > 0.5:
            # Оба метода видят аномалию
            agreement_boost = 1.2
            combined = min(1.0, combined * agreement_boost)
        
        # Если хотя бы один метод очень уверен
        if statistical_score > 0.8 or ml_score > 0.8:
            combined = max(combined, max(statistical_score, ml_score) * 0.9)
        
        return min(1.0, combined)
    
    def _determine_threat_level(self, score: float) -> str:
        """Определение уровня угрозы по скору"""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        elif score >= 0.3:
            return "low"
        else:
            return "none"
    
    def _recommend_action(self, assessment: ThreatAssessment) -> str:
        """Рекомендация действия на основе оценки"""
        
        # Сигнатура сработала - блокировать
        if assessment.signature_score >= 1.0:
            return "block"
        
        # По уровню угрозы
        if assessment.threat_level == "critical":
            return "block"
        elif assessment.threat_level == "high":
            return "alert"
        elif assessment.threat_level == "medium":
            return "alert"
        elif assessment.threat_level == "low":
            return "monitor"
        else:
            return "none"
    
    def get_stats(self) -> Dict:
        """Статистика"""
        uptime = time.time() - self.start_time
        return {
            "total_assessments": int(self.total_assessments),
            "threats_detected": int(self.threats_detected),
            "threat_rate": float(round(self.threats_detected / max(self.total_assessments, 1), 4)),
            "uptime_seconds": float(round(uptime, 2)),
            "config": {
                "alert_threshold": float(self.config.alert_threshold),
                "weight_statistical": float(self.config.weight_statistical),
                "weight_ml": float(self.config.weight_ml),
            }
        }


class BehavioralEngine:
    """
    Главный движок поведенческого анализа
    
    Объединяет все компоненты:
    - Feature Extractor
    - Statistical Analyzer
    - ML Model (Isolation Forest)
    - Score Fusion
    """
    
    def __init__(self, config: BehavioralConfig = None):
        self.config = config or BehavioralConfig()
        
        # Импорт компонентов
        from feature_extractor import FeatureExtractor
        from statistical_analyzer import StatisticalAnalyzer
        
        self.feature_extractor = FeatureExtractor(
            window_sec=self.config.time_window
        )
        self.statistical_analyzer = StatisticalAnalyzer(self.config)
        self.score_fusion = ScoreFusion(self.config)
        
        # ML модель (опционально)
        self.ml_model = None
        try:
            from ml_model import IsolationForestModel
            self.ml_model = IsolationForestModel(self.config)
        except Exception as e:
            logging.warning(f"ML model not available: {e}")
        
        self.logger = logging.getLogger("BehavioralEngine")
        self.start_time = time.time()
    
    def process_packet(self, packet_data: Dict):
        """Обработка пакета"""
        self.feature_extractor.process_packet_dict(packet_data)
    
    def analyze(self, src_ip: str, signature_score: float = 0.0,
                signature_details: Dict = None) -> ThreatAssessment:
        """
        Полный анализ IP-адреса
        
        Args:
            src_ip: IP для анализа
            signature_score: Результат сигнатурного анализа (от Go-движка)
            signature_details: Детали сигнатурного анализа
            
        Returns:
            ThreatAssessment с полной оценкой
        """
        # Получение признаков
        features = self.feature_extractor.get_features(src_ip)
        
        if features is None:
            # Нет данных по этому IP
            return ThreatAssessment(
                src_ip=src_ip,
                timestamp=time.time(),
                signature_score=signature_score,
                signature_details=signature_details or {},
            )
        
        # Статистический анализ
        stat_result = self.statistical_analyzer.analyze(features)
        
        # ML анализ
        ml_score = 0.0
        ml_details = {}
        
        if self.ml_model and self.ml_model.is_trained:
            ml_result = self.ml_model.predict(features)
            ml_score = ml_result.anomaly_score
            ml_details = ml_result.to_dict()
        
        # Объединение результатов
        assessment = self.score_fusion.assess(
            src_ip=src_ip,
            signature_score=signature_score,
            signature_details=signature_details,
            statistical_score=stat_result.anomaly_score,
            statistical_details=stat_result.to_dict(),
            ml_score=ml_score,
            ml_details=ml_details,
        )
        
        return assessment
    
    def train_ml_model(self, clean_traffic_duration: int = 60) -> Dict:
        """
        Обучение ML модели на текущем трафике
        
        Предполагается, что трафик в данный момент "чистый"
        """
        if not self.ml_model:
            return {"error": "ML model not available"}
        
        features_list = list(self.feature_extractor.get_all_features().values())
        
        if len(features_list) < 10:
            return {"error": f"Need more data. Have {len(features_list)} samples"}
        
        result = self.ml_model.train(features_list)
        
        if "error" not in result:
            self.ml_model.save()
        
        return result
    
    def load_ml_model(self, path: str = None) -> bool:
        """Загрузка сохранённой ML модели"""
        if not self.ml_model:
            return False
        return self.ml_model.load(path)
    
    def update_baseline(self):
        """Обновление baseline для статистического анализа"""
        features_list = list(self.feature_extractor.get_all_features().values())
        for features in features_list:
            self.statistical_analyzer.update_baseline(features)
    
    def get_stats(self) -> Dict:
        """Полная статистика движка"""
        stats = {
            "uptime_seconds": round(time.time() - self.start_time, 2),
            "feature_extractor": self.feature_extractor.get_stats(),
            "statistical_analyzer": self.statistical_analyzer.get_stats(),
            "score_fusion": self.score_fusion.get_stats(),
        }
        
        if self.ml_model:
            stats["ml_model"] = self.ml_model.get_stats()
        
        return stats


# Глобальный движок
_engine: Optional[BehavioralEngine] = None


def get_engine() -> BehavioralEngine:
    """Получение глобального движка"""
    global _engine
    if _engine is None:
        _engine = BehavioralEngine()
    return _engine


if __name__ == "__main__":
    # Тест Score Fusion
    fusion = ScoreFusion()
    
    print("=== Тест Score Fusion ===\n")
    
    # Тест 1: Сигнатура сработала
    result = fusion.assess(
        src_ip="192.168.1.100",
        signature_score=1.0,
        statistical_score=0.3,
        ml_score=0.2,
    )
    print(f"Тест 1 (сигнатура): {result.to_dict()}\n")
    
    # Тест 2: Только behavioral
    result = fusion.assess(
        src_ip="192.168.1.101",
        signature_score=0.0,
        statistical_score=0.7,
        ml_score=0.8,
    )
    print(f"Тест 2 (behavioral): {result.to_dict()}\n")
    
    # Тест 3: Нормальный трафик
    result = fusion.assess(
        src_ip="192.168.1.102",
        signature_score=0.0,
        statistical_score=0.1,
        ml_score=0.15,
    )
    print(f"Тест 3 (нормальный): {result.to_dict()}\n")
    
    # Тест 4: Один метод уверен
    result = fusion.assess(
        src_ip="192.168.1.103",
        signature_score=0.0,
        statistical_score=0.2,
        ml_score=0.9,
    )
    print(f"Тест 4 (ML уверен): {result.to_dict()}\n")
    
    print(f"Статистика: {fusion.get_stats()}")
