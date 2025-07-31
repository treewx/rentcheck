# RentCheck Production Deployment Guide

## Production Readiness Checklist ✅

### Security Fixes Implemented
- ✅ **Bcrypt Password Hashing** - Replaced SHA-256 with secure bcrypt hashing
- ✅ **Environment Variables** - Removed hardcoded credentials, using .env files
- ✅ **Input Validation** - Added WTForms validation for all user inputs
- ✅ **CSRF Protection** - Flask-WTF CSRF tokens on all forms
- ✅ **Session Security** - Secure session configuration with timeouts
- ✅ **Rate Limiting** - Applied to login (10/min) and registration (3/min)
- ✅ **Security Headers** - XSS, CSRF, clickjacking protection
- ✅ **Error Handling** - Proper logging and error pages
- ✅ **Email Validation** - Server-side email format validation

## Pre-Deployment Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration
Copy `.env.template` to `.env` and configure:

```bash
cp .env.template .env
```

**Required Environment Variables:**
```env
SECRET_KEY=your-32-character-random-secret-key
EMAIL_SENDER=your-email@gmail.com
EMAIL_PASSWORD=your-gmail-app-password
DATABASE_URL=sqlite:///rentcheck.db
SESSION_COOKIE_SECURE=True  # Set to True for HTTPS
```

**Generate Secret Key:**
```python
import secrets
print(secrets.token_hex(32))
```

### 3. Database Migration
The app will automatically create/migrate database tables on startup.

## Production Deployment Options

### Option 1: Gunicorn (Recommended)
```bash
# Create logs directory
mkdir -p logs

# Start with Gunicorn
gunicorn -c gunicorn.conf.py wsgi:app

# Or manually:
gunicorn --bind 0.0.0.0:8000 --workers 4 wsgi:app
```

### Option 2: Docker (Future)
```dockerfile
# Dockerfile template for future use
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
```

## Nginx Configuration
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static/ {
        alias /path/to/rentcheck/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

## SSL/HTTPS Setup
```bash
# Using Let's Encrypt (Certbot)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com

# Update .env
SESSION_COOKIE_SECURE=True
```

## Database Upgrade (Production)
For production, consider upgrading from SQLite:

### PostgreSQL Setup
```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Create database
sudo -u postgres createdb rentcheck
sudo -u postgres createuser rentcheck_user

# Update .env
DATABASE_URL=postgresql://rentcheck_user:password@localhost/rentcheck
```

### MySQL Setup
```bash
# Update .env
DATABASE_URL=mysql://user:password@localhost/rentcheck
```

## Monitoring & Logging

### Log Files
- Application logs: `logs/rentcheck.log`
- Access logs: `logs/access.log`
- Error logs: `logs/error.log`

### Log Rotation
```bash
# Add to logrotate
sudo nano /etc/logrotate.d/rentcheck
```

```
/path/to/rentcheck/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 0644 www-data www-data
}
```

## Security Considerations

### Firewall
```bash
# UFW setup
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### Regular Updates
```bash
# Schedule automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```

### Backup Strategy
```bash
# Automated daily backups
0 2 * * * /usr/bin/sqlite3 /path/to/rentcheck.db ".backup /backups/rentcheck-$(date +\%Y\%m\%d).db"
```

## Performance Optimization

### Static File Serving
Configure Nginx to serve static files directly for better performance.

### Caching (Future Enhancement)
Consider adding Redis for session storage and caching:
```env
RATELIMIT_STORAGE_URL=redis://localhost:6379/0
```

## Remaining Development Tasks

### High Priority
- [ ] **Payment Processing** - Stripe integration for subscriptions
- [ ] **Subscription Management** - Billing cycles and plan limits
- [ ] **Email Verification** - Verify user email addresses on signup

### Medium Priority  
- [ ] **Usage Analytics** - Track user engagement and usage
- [ ] **Password Reset** - Forgot password functionality
- [ ] **2FA Authentication** - Two-factor authentication option

### Production Monitoring
- [ ] **Health Checks** - Application health monitoring endpoint
- [ ] **Performance Monitoring** - APM integration (New Relic, DataDog)
- [ ] **Uptime Monitoring** - External service monitoring

## Estimated Timeline
- **Current State**: MVP with production-ready security fixes ✅
- **Payment Integration**: 1-2 weeks additional development
- **Full Production Ready**: 3-4 weeks with monitoring and optimization

## Support & Maintenance
- Regular security updates
- Database backups and recovery procedures  
- Performance monitoring and optimization
- User support and bug fixes