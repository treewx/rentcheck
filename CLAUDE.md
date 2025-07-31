# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RentCheck is a Flask-based web application that helps landlords monitor rental payments through automated bank transaction monitoring via the Akahu API. The application provides real-time payment tracking, automated email notifications for overdue rent, and a web dashboard for property management.

## Development Commands

### Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Application Access
- Web interface: http://localhost:5001
- Development server runs on port 5001 with debug mode enabled

## Architecture

### Core Components
- **Flask Application** (`app.py`): Single-file monolithic architecture with all routes, database operations, and business logic
- **SQLite Database** (`rentcheck.db`): Auto-created with 4 main tables:
  - `properties`: Property and tenant information with payment keywords
  - `payment_history`: Transaction records and payment tracking
  - `user_settings`: API credentials and configuration storage
  - `akahu_accounts`: Bank account management for payment monitoring
- **HTML Templates**: Bootstrap-styled responsive templates with embedded CSS
- **Background Scheduler**: APScheduler for daily overdue payment checks at 9 AM

### Key Integration Points
- **Akahu Banking API**: Real-time transaction fetching with configurable account filtering
- **Email Notifications**: Gmail SMTP integration for automated rent alerts
- **Payment Matching**: Keyword-based transaction matching with 90% amount tolerance

### Configuration Management
- API credentials stored in database via settings system (not environment variables)
- Email configuration hardcoded in `EMAIL_CONFIG` dictionary
- No external config files - all settings managed through web interface

### Database Design Patterns
- Context manager pattern for database connections (`get_db()`)
- Dynamic settings system with key-value storage
- Automatic schema migration for adding new columns
- Foreign key relationships between properties and payment history

### API Architecture
- RESTful endpoints for CRUD operations on properties
- JSON response format for AJAX operations
- Background job processing for scheduled payment checks
- Error handling with JSON error responses

## Security Considerations

### Current Security Model
- No user authentication system implemented
- All credentials (API keys and email settings) stored securely in database via settings system
- No hardcoded credentials in source code
- Single-user application design
- Email and API credentials configurable through web interface

## Key Development Patterns

### Database Operations
- All database access uses context manager pattern with automatic connection cleanup
- SQLite Row factory for dict-like access to results
- Prepared statements for SQL injection prevention

### Error Handling
- Try-catch blocks with JSON error responses
- Console logging for debugging and monitoring
- Graceful degradation when API services unavailable

### API Integration
- Requests library for external API calls
- Header-based authentication with Akahu API
- Batch transaction processing across multiple accounts
- Rate limiting consideration for API calls

## Common Development Tasks

### Adding New Properties
Properties require: name, tenant, rent amount, due day, payment frequency, and payment keyword for transaction matching.

### Modifying Payment Logic
Payment matching logic in `check_property_payment()` function uses:
- Case-insensitive keyword matching in transaction descriptions
- 90% amount tolerance for partial payments
- 7-day transaction window for payment detection

### Database Schema Changes
Use the migration pattern shown for adding `payment_frequency` column - handle `sqlite3.OperationalError` for existing columns.

### Email Configuration
Email settings managed through database settings system:
- `email_sender`: Sender email address  
- `email_password`: App password for Gmail SMTP
- `email_recipient`: Notification recipient email

### Email Template Customization
Email content generated in `check_overdue_payments()` function with hardcoded formatting.