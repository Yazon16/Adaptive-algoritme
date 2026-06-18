#!/usr/bin/env python3
"""
Behavioral Analysis Module - API Server

REST API для взаимодействия с Go-движком и управления поведенческим анализом.

Endpoints:
- POST /api/packet      - Принять пакет для анализа
- POST /api/analyze     - Анализировать IP
- GET  /api/stats       - Статистика
- POST /api/train       - Обучить ML модель
- GET  /api/health      - Проверка состояния
"""

import argparse
import json
import logging
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional

# Добавляем текущую директорию в path
sys.path.insert(0, '.')

from config import BehavioralConfig, config
from feature_extractor import FeatureExtractor, PacketInfo, get_extractor
from statistical_analyzer import StatisticalAnalyzer, get_analyzer
from score_fusion import BehavioralEngine, get_engine

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('behavioral.log'),
    ]
)
logger = logging.getLogger("BehavioralAPI")


class BehavioralAPIHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler для Behavioral API"""
    
    engine: BehavioralEngine = None
    
    def log_message(self, format, *args):
        """Переопределение логирования"""
        logger.debug(f"{self.address_string()} - {format % args}")
    
    def _send_json(self, data: Dict, status: int = 200):
        """Отправка JSON ответа"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _read_json(self) -> Optional[Dict]:
        """Чтение JSON из тела запроса"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                return {}
            body = self.rfile.read(content_length)
            return json.loads(body.decode())
        except Exception as e:
            logger.error(f"Error reading JSON: {e}")
            return None
    
    def do_OPTIONS(self):
        """CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        """Обработка GET запросов"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == '/api/health':
            self._handle_health()
        elif path == '/api/stats':
            self._handle_stats()
        elif path == '/api/features':
            self._handle_get_features(parsed)
        elif path == '/api/baseline':
            self._handle_baseline_status()
        else:
            self._send_json({"error": "Not found"}, 404)
    
    def do_POST(self):
        """Обработка POST запросов"""
        parsed = urlparse(self.path)
        path = parsed.path
        
        data = self._read_json()
        if data is None:
            self._send_json({"error": "Invalid JSON"}, 400)
            return
        
        if path == '/api/packet':
            self._handle_packet(data)
        elif path == '/api/packets':
            self._handle_packets_batch(data)
        elif path == '/api/analyze':
            self._handle_analyze(data)
        elif path == '/api/train':
            self._handle_train(data)
        elif path == '/api/baseline/update':
            self._handle_update_baseline()
        elif path == '/api/model/load':
            self._handle_load_model(data)
        elif path == '/api/model/save':
            self._handle_save_model(data)
        else:
            self._send_json({"error": "Not found"}, 404)
    
    # === Handlers ===
    
    def _handle_health(self):
        """Проверка состояния"""
        self._send_json({
            "status": "ok",
            "service": "behavioral-module",
            "timestamp": time.time(),
        })
    
    def _handle_stats(self):
        """Статистика модуля"""
        stats = self.engine.get_stats()
        self._send_json(stats)
    
    def _handle_packet(self, data: Dict):
        """Приём одного пакета"""
        try:
            self.engine.process_packet(data)
            self._send_json({"status": "ok"})
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self._send_json({"error": str(e)}, 500)
    
    def _handle_packets_batch(self, data: Dict):
        """Приём пакета пакетов"""
        try:
            packets = data.get("packets", [])
            for packet in packets:
                self.engine.process_packet(packet)
            self._send_json({"status": "ok", "processed": len(packets)})
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
            self._send_json({"error": str(e)}, 500)
    
    def _handle_analyze(self, data: Dict):
        """Анализ IP-адреса"""
        src_ip = data.get("src_ip")
        if not src_ip:
            self._send_json({"error": "src_ip required"}, 400)
            return
        
        signature_score = data.get("signature_score", 0.0)
        signature_details = data.get("signature_details", {})
        
        try:
            assessment = self.engine.analyze(
                src_ip=src_ip,
                signature_score=signature_score,
                signature_details=signature_details,
            )
            
            result = assessment.to_dict()
            
            # Логирование угроз
            if assessment.is_threat:
                logger.warning(
                    f"[THREAT] {src_ip} | Level: {assessment.threat_level} | "
                    f"Score: {assessment.final_score:.3f} | "
                    f"Action: {assessment.recommended_action}"
                )
            
            self._send_json(result)
            
        except Exception as e:
            logger.error(f"Error analyzing {src_ip}: {e}")
            self._send_json({"error": str(e)}, 500)
    
    def _handle_get_features(self, parsed):
        """Получение признаков для IP"""
        query = parse_qs(parsed.query)
        src_ip = query.get("ip", [None])[0]
        
        if src_ip:
            features = self.engine.feature_extractor.get_features(src_ip)
            if features:
                self._send_json(features.to_dict())
            else:
                self._send_json({"error": "IP not found"}, 404)
        else:
            # Все признаки
            all_features = self.engine.feature_extractor.get_all_features()
            result = {ip: f.to_dict() for ip, f in all_features.items()}
            self._send_json(result)
    
    def _handle_train(self, data: Dict):
        """Обучение ML модели"""
        try:
            result = self.engine.train_ml_model()
            
            if "error" in result:
                self._send_json(result, 400)
            else:
                logger.info(f"ML model trained: {result}")
                self._send_json(result)
                
        except Exception as e:
            logger.error(f"Error training model: {e}")
            self._send_json({"error": str(e)}, 500)
    
    def _handle_update_baseline(self):
        """Обновление baseline"""
        try:
            self.engine.update_baseline()
            self._send_json({"status": "ok", "message": "Baseline updated"})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
    
    def _handle_baseline_status(self):
        """Статус baseline"""
        stats = self.engine.statistical_analyzer.get_stats()
        self._send_json(stats)
    
    def _handle_load_model(self, data: Dict):
        """Загрузка ML модели"""
        path = data.get("path")
        try:
            success = self.engine.load_ml_model(path)
            if success:
                self._send_json({"status": "ok", "message": "Model loaded"})
            else:
                self._send_json({"error": "Failed to load model"}, 400)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)
    
    def _handle_save_model(self, data: Dict):
        """Сохранение ML модели"""
        path = data.get("path")
        try:
            if self.engine.ml_model:
                success = self.engine.ml_model.save(path)
                if success:
                    self._send_json({"status": "ok", "message": "Model saved"})
                else:
                    self._send_json({"error": "Model not trained"}, 400)
            else:
                self._send_json({"error": "ML model not available"}, 400)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)


def run_server(host: str = "0.0.0.0", port: int = 8081):
    """Запуск HTTP сервера"""
    
    # Инициализация движка
    engine = get_engine()
    BehavioralAPIHandler.engine = engine
    
    # Попытка загрузить сохранённую модель
    if engine.ml_model:
        if engine.load_ml_model():
            logger.info("Loaded saved ML model")
        else:
            logger.info("No saved ML model found, will need training")
    
    server = HTTPServer((host, port), BehavioralAPIHandler)
    
    logger.info(f"Behavioral Analysis Module started on {host}:{port}")
    logger.info("Endpoints:")
    logger.info("  GET  /api/health      - Health check")
    logger.info("  GET  /api/stats       - Statistics")
    logger.info("  GET  /api/features    - Get features (?ip=x.x.x.x)")
    logger.info("  GET  /api/baseline    - Baseline status")
    logger.info("  POST /api/packet      - Process single packet")
    logger.info("  POST /api/packets     - Process packet batch")
    logger.info("  POST /api/analyze     - Analyze IP")
    logger.info("  POST /api/train       - Train ML model")
    logger.info("  POST /api/baseline/update - Update baseline")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(description="Behavioral Analysis Module")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", "-p", type=int, default=8081, help="Port to bind")
    parser.add_argument("--config", "-c", help="Config file path")
    
    args = parser.parse_args()
    
    # Загрузка конфига
    if args.config:
        global config
        config = BehavioralConfig.from_file(args.config)
    
    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
