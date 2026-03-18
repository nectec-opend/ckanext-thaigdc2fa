# ckanext-thaigdc2fa

CKAN extension สำหรับเพิ่ม **Two-Factor Authentication (2FA)** แบบ **TOTP**  
รองรับแอปเช่น

- Google Authenticator
- Microsoft Authenticator
- Authy

ผู้ใช้ต้องกรอก **OTP 6 หลัก** หลังจาก login เพื่อเพิ่มความปลอดภัย

---

# Requirements

- CKAN 2.10+
- Python 3.8+

---

# Installation

Activate CKAN virtualenv

```bash
source /usr/lib/ckan/default/bin/activate
```
Clone Extension
```
cd /usr/lib/ckan/default/src
git clone https://github.com/nectec-opend/ckanext-thaigdc2fa.git
```
Install
```
cd ckanext-thaigdc2fa
pip install -e .
```
Install dependencies
```
pip install -r requirements.txt
```
# Enable Plugin
เพิ่มใน ckan.ini
```
ckan.plugins = ... thaigdc2fa
```
# Configuration
สร้าง secret key
```
python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```
เพิ่มใน ckan.ini
```
ckanext.thaigdc2fa.cipher_key = YOUR_SECRET_KEY
```

# Restart CKAN Service
```
sudo supervisorctl reload
```