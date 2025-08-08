# 🚀 ColorBot API Server (Vercel)

## 📋 Açıklama
ColorBot lisans yönetim sistemi için Vercel API server'ı.

## 🌐 API Endpoints

### Health Check
```
GET /api/health
```

### License Validation
```
POST /api/license/validate
Content-Type: application/json
X-API-Key: QUARX_API_SECRET_2024

{
  "license_key": "QUA-TEST-1234-5678-9ABC-DEF0-1234",
  "hardware_id": "abc123..."
}
```

### License Activation
```
POST /api/license/activate
Content-Type: application/json
X-API-Key: QUARX_API_SECRET_2024

{
  "license_key": "QUA-TEST-1234-5678-9ABC-DEF0-1234",
  "username": "test_user",
  "email": "test@example.com",
  "hardware_id": "abc123..."
}
```

### License Status
```
GET /api/license/status?license_key=QUA-TEST-1234-5678-9ABC-DEF0-1234
X-API-Key: QUARX_API_SECRET_2024
```

## 🔧 Kurulum

1. Vercel'e deploy et
2. API URL'ini al: `https://colorbot-api2-xxx.vercel.app`
3. Client'ları güncelle

## 📊 Veritabanı

- SQLite kullanılıyor
- Vercel'de `/tmp/` klasöründe geçici olarak saklanıyor
- Otomatik tablo oluşturma

## 🔒 Güvenlik

- API Key: `QUARX_API_SECRET_2024`
- Hardware ID binding
- IP logging
- Request validation
