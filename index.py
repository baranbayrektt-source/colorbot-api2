#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ColorBot API Server for Vercel
"""

from flask import Flask, request, jsonify
import sqlite3
import json
import hashlib
import time
from datetime import datetime, timedelta
import threading
import logging
import os

# Logging ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)

class ColorBotAPI:
    def __init__(self):
        # Vercel'de geçici dosya sistemi kullan
        self.db_path = "/tmp/license_database.db" if os.environ.get('VERCEL') else "license_database.db"
        self.api_key = "QUARX_API_SECRET_2024"  # Güvenlik için API key
        self.init_database()
    
    def init_database(self):
        """Veritabanını başlat"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Licenses tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT UNIQUE NOT NULL,
                    license_type TEXT NOT NULL,
                    created_date TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    is_used INTEGER DEFAULT 0,
                    used_by TEXT,
                    generated_by TEXT DEFAULT 'admin',
                    price REAL DEFAULT 0.0,
                    hardware_id TEXT,
                    last_check TEXT
                )
            ''')
            
            # Users tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    email TEXT,
                    license_key TEXT,
                    created_date TEXT,
                    expiry_date TEXT,
                    is_active INTEGER DEFAULT 1,
                    last_login TEXT,
                    login_count INTEGER DEFAULT 0,
                    hardware_id TEXT,
                    ip_address TEXT
                )
            ''')
            
            # API logs tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    endpoint TEXT,
                    method TEXT,
                    ip_address TEXT,
                    timestamp TEXT,
                    response_code INTEGER,
                    user_agent TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            logging.info("✅ Veritabanı başlatıldı")
            
        except Exception as e:
            logging.error(f"❌ Veritabanı başlatma hatası: {e}")
    
    def log_request(self, endpoint, method, ip_address, response_code, user_agent):
        """API isteklerini logla"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO api_logs (endpoint, method, ip_address, timestamp, response_code, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (endpoint, method, ip_address, datetime.now().isoformat(), response_code, user_agent))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"❌ Log hatası: {e}")
    
    def verify_api_key(self, request):
        """API key doğrulama"""
        api_key = request.headers.get('X-API-Key')
        return api_key == self.api_key

# Global API instance
api = ColorBotAPI()

@app.route('/health', methods=['GET'])
def health_check():
    """API sağlık kontrolü"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'platform': 'vercel' if os.environ.get('VERCEL') else 'local'
    })

@app.route('/license/validate', methods=['POST'])
def validate_license():
    """Lisans doğrulama endpoint'i"""
    try:
        if not api.verify_api_key(request):
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        license_key = data.get('license_key')
        hardware_id = data.get('hardware_id')
        client_ip = request.remote_addr
        
        if not license_key:
            return jsonify({'error': 'License key required'}), 400
        
        # Veritabanında kontrol et
        conn = sqlite3.connect(api.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT license_key, license_type, expiry_date, is_used, used_by, price
            FROM licenses 
            WHERE license_key = ?
        ''', (license_key,))
        
        result = cursor.fetchone()
        
        if not result:
            api.log_request('/license/validate', 'POST', client_ip, 404, request.headers.get('User-Agent'))
            return jsonify({'valid': False, 'message': 'Lisans anahtarı bulunamadı'}), 404
        
        key, license_type, expiry_date, is_used, used_by, price = result
        
        # Süre kontrolü
        expiry = datetime.fromisoformat(expiry_date)
        now = datetime.now()
        
        if expiry < now:
            api.log_request('/license/validate', 'POST', client_ip, 403, request.headers.get('User-Agent'))
            return jsonify({'valid': False, 'message': 'Lisans süresi dolmuş'}), 403
        
        # Son kontrol zamanını güncelle
        cursor.execute('''
            UPDATE licenses SET last_check = ? WHERE license_key = ?
        ''', (now.isoformat(), license_key))
        
        conn.commit()
        conn.close()
        
        license_data = {
            'key': key,
            'type': license_type,
            'expiry_date': expiry_date,
            'is_used': is_used,
            'used_by': used_by,
            'price': price,
            'days_remaining': (expiry - now).days
        }
        
        api.log_request('/license/validate', 'POST', client_ip, 200, request.headers.get('User-Agent'))
        return jsonify({'valid': True, 'license_data': license_data}), 200
        
    except Exception as e:
        logging.error(f"Lisans doğrulama hatası: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/license/activate', methods=['POST'])
def activate_license():
    """Lisans aktivasyon endpoint'i"""
    try:
        if not api.verify_api_key(request):
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        license_key = data.get('license_key')
        username = data.get('username')
        email = data.get('email')
        hardware_id = data.get('hardware_id')
        client_ip = request.remote_addr
        
        if not license_key:
            return jsonify({'error': 'License key required'}), 400
        
        # Veritabanında kontrol et
        conn = sqlite3.connect(api.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT license_key, license_type, expiry_date, is_used, used_by
            FROM licenses 
            WHERE license_key = ?
        ''', (license_key,))
        
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'Lisans anahtarı bulunamadı'}), 404
        
        key, license_type, expiry_date, is_used, used_by = result
        
        # Süre kontrolü
        expiry = datetime.fromisoformat(expiry_date)
        now = datetime.now()
        
        if expiry < now:
            return jsonify({'success': False, 'message': 'Lisans süresi dolmuş'}), 403
        
        # Aktivasyon
        cursor.execute('''
            UPDATE licenses 
            SET is_used = 1, used_by = ?, hardware_id = ?, last_check = ?
            WHERE license_key = ?
        ''', (username or 'unknown', hardware_id, now.isoformat(), license_key))
        
        # Kullanıcı kaydı
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, email, license_key, created_date, expiry_date, last_login, hardware_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, license_key, now.isoformat(), expiry_date, now.isoformat(), hardware_id))
        
        conn.commit()
        conn.close()
        
        api.log_request('/license/activate', 'POST', client_ip, 200, request.headers.get('User-Agent'))
        return jsonify({'success': True, 'message': 'Lisans aktifleştirildi'}), 200
        
    except Exception as e:
        logging.error(f"Lisans aktivasyon hatası: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/license/status', methods=['GET'])
def get_license_status():
    """Lisans durumu endpoint'i"""
    try:
        if not api.verify_api_key(request):
            return jsonify({'error': 'Unauthorized'}), 401
        
        license_key = request.args.get('license_key')
        client_ip = request.remote_addr
        
        if not license_key:
            return jsonify({'error': 'License key required'}), 400
        
        # Veritabanında kontrol et
        conn = sqlite3.connect(api.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT license_key, license_type, expiry_date, is_used, used_by, price, hardware_id, last_check
            FROM licenses 
            WHERE license_key = ?
        ''', (license_key,))
        
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'error': 'Lisans anahtarı bulunamadı'}), 404
        
        key, license_type, expiry_date, is_used, used_by, price, hardware_id, last_check = result
        
        license_data = {
            'key': key,
            'type': license_type,
            'expiry_date': expiry_date,
            'is_used': is_used,
            'used_by': used_by,
            'price': price,
            'hardware_id': hardware_id,
            'last_check': last_check,
            'days_remaining': (datetime.fromisoformat(expiry_date) - datetime.now()).days
        }
        
        conn.close()
        
        api.log_request('/license/status', 'GET', client_ip, 200, request.headers.get('User-Agent'))
        return jsonify({'license_data': license_data}), 200
        
    except Exception as e:
        logging.error(f"Lisans durumu hatası: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Vercel için app'i export et
app.debug = False
