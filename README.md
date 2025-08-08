# 🚀 ColorBot API Server (Vercel)

ColorBot lisans yönetim sistemi için Vercel API server'ı.

## 🌐 API Endpoints

- `GET /api/health` - Health check
- `POST /api/license/validate` - License validation
- `POST /api/license/activate` - License activation
- `GET /api/license/status` - License status

## 🔧 Deployment

Bu proje Vercel'de deploy edilmek üzere tasarlanmıştır.

### Requirements
- Flask 2.3.3
- Python 3.9+

### Environment Variables
- `API_KEY`: QUARX_API_SECRET_2024

## 📊 Database
# Test Update

SQLite veritabanı kullanılıyor. Vercel'de `/tmp/` klasöründe geçici olarak saklanıyor.
