# OSDU Record Viewer

Ứng dụng Flask đơn giản để xem các record OSDU theo domain và entities với quản lý token tự động.

## 🏗️ Cấu trúc

```
osdu_view/
├── app.py                 # Flask app chính
├── config.py              # Quản lý cấu hình
├── token_manager.py       # Quản lý access token
├── domains.py             # Định nghĩa domains và entities
├── .env                   # Biến môi trường
├── requirements.txt       # Dependencies
├── templates/             # HTML templates
│   ├── home.html          # Trang chủ
│   ├── domain.html        # Trang domain
│   ├── records.html       # Danh sách records
│   └── record_detail.html # Chi tiết record
└── static/
    └── style.css          # CSS styles
```

## ⚙️ Cài đặt

1. **Cài đặt dependencies:**
```bash
pip install -r requirements.txt
```

2. **Cấu hình file .env:**
```bash
# Sao chép .env.example và điền thông tin
cp .env .env.local
nano .env
```

3. **Điền thông tin OSDU trong .env:**
```env
OSDU_BASE_URL=http://osdu.huulinhcvp.click
OSDU_BASE_HOST=osdu.huulinhcvp.click
OSDU_PARTITION_ID=osdu
OSDU_TOKEN_ENDPOINT=http://keycloak.osdu.huulinhcvp.click/realms/osdu/protocol/openid-connect/token
OSDU_TOKEN_HOST=keycloak.osdu.huulinhcvp.click
OSDU_CLIENT_ID=datafier
OSDU_CLIENT_SECRET=your_client_secret
OSDU_VERIFY_SSL=False
```

## 🚀 Chạy ứng dụng

```bash
python app.py
```

Truy cập: http://localhost:5000

## 🎯 Tính năng

### 📊 Domains được hỗ trợ:
- **General Data** (8 entities): Basin, Block, Field, Reservoir, Well, Wellbore, GeopoliticalEntity, Organisation
- **Wellbore Domain** (7 entities): WellLog, WellboreTrajectory, WellboreMarkerSet, WellboreCompletion, WellLogChannel, LoggingTool, CoredInterval
- **Work/Project Domain** (5 entities): Project, WorkProduct, WorkProductComponent, Activity, ActivityTemplate  
- **Seismic Domain** (5 entities): SeismicSurvey, Seismic2D, Seismic3D, SeismicLine, SeismicAcquisitionSurvey
- **Files Domain** (3 entities): File, Dataset, FileCollection
- **Reference Domain** (3 entities): ReferenceData, Unit, CRS

### ✨ Chức năng:
- 🏠 **Trang chủ**: Xem tất cả domains với search
- 📁 **Domain page**: Xem entities trong domain  
- 📋 **Records page**: Danh sách records với:
  - Pagination thông minh
  - Filter theo fields
  - Export JSON/CSV
  - Real-time loading
- 📄 **Record detail**: Chi tiết record với:
  - JSON view / Tree view
  - Copy/Download JSON/CSV
  - Thống kê chi tiết
  - Keyboard shortcuts

### 🔐 Token Management:
- Tự động lấy và refresh token
- Cache token trong memory và file
- Fallback từ refresh_token sang client_credentials
- Xử lý lỗi và retry logic

### 🎨 UI/UX:
- Responsive design tối ưu mobile
- Dark/Light theme adaptation
- Smooth animations và transitions
- Loading states và error handling
- Search và filter real-time

## 🔧 API Endpoints

- `GET /` - Trang chủ
- `GET /domain/{domain}` - Trang domain
- `GET /records/{domain}/{entity}` - Danh sách records
- `GET /record/{record_id}` - Chi tiết record
- `GET /api/records/{domain}/{entity}` - API lấy records
- `GET /api/record/{record_id}` - API chi tiết record
- `GET /api/health` - Health check

## 📋 Query Parameters

### Records API:
- `limit`: Số lượng records (max 1000)  
- `offset`: Offset cho pagination
- `fields`: Trường hiển thị (`basic`, `all`, hoặc tên field cụ thể)

## 🔧 Troubleshooting

### Token issues:
```bash
# Check health
curl http://localhost:5000/api/health

# Clear token cache
rm .token_cache
```

### Cấu hình issues:
```bash
# Validate env
python -c "from config import config; config.validate(); print('OK')"
```

## 🚀 Production Deployment 

### With Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### With Docker:
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## 📝 Notes

- Token được cache 5 phút trước khi hết hạn
- Default limit 50 records để tối ưu performance  
- SSL verification có thể tắt trong dev environment
- Logs được ghi ở level INFO
- Keyboard shortcuts: Ctrl+R (reload), Ctrl+C (copy), Ctrl+S (save), Ctrl+T (toggle view)