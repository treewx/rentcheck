# RentCheck - Automated Rent Payment Monitoring

A production-ready multi-user Flask application for landlords to monitor rental payments through automated bank transaction monitoring via the Akahu API.

🚀 **Live Demo**: [Deployed on Railway](https://your-railway-url-here.railway.app)

## Features

### 🏠 Property Management
- Add, edit, and delete rental properties
- Store tenant information and rent amounts
- Set rent due days and payment keywords for bank transaction matching

### 💳 Payment Tracking
- Automatic integration with Akahu banking API
- Real-time rent payment detection
- Payment history tracking
- Visual dashboard with payment status

### 📧 Smart Notifications
- Automated daily email alerts for overdue payments
- Manual payment checks
- Test email functionality

### 📊 Dashboard
- Overview of all properties and their payment status
- Recent payment history
- Statistics on total properties and rent amounts

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python app.py
```

### 3. Access the Web App
Open your browser and go to: `http://localhost:5001`

## Usage

### Adding Properties
1. Go to "Property Management" from the dashboard
2. Click "Add New Property"
3. Fill in the property details:
   - **Property Name**: Address or property identifier
   - **Tenant Name**: Current tenant's name
   - **Rent Amount**: Monthly rent amount
   - **Due Day**: Day of the week rent is due
   - **Payment Keyword**: Text to search for in bank transactions

### Checking Payments
1. From the dashboard, click "Check Payments"
2. The app will automatically fetch recent bank transactions
3. It matches transactions using the payment keywords
4. Payment status is updated in real-time

### Email Notifications
- The app automatically checks for overdue payments daily at 9 AM
- You'll receive email alerts for any missing payments
- Test the email system with the `/send_test_email` endpoint

## Configuration

### Bank Integration (Akahu API)
The app is pre-configured with Akahu API credentials. Update `AKAHU_CONFIG` in `app.py` if needed:

```python
AKAHU_CONFIG = {
    "app_token": "your_app_token",
    "user_token": "your_user_token", 
    "account_id": "your_account_id"
}
```

### Email Settings
Update `EMAIL_CONFIG` in `app.py` with your email credentials:

```python
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_email@gmail.com",
    "sender_password": "your_app_password",
    "recipient_email": "your_email@gmail.com"
}
```

## Database

The app uses SQLite database (`rentcheck.db`) with two main tables:
- `properties`: Store property and tenant information
- `payment_history`: Track payment records

## API Endpoints

- `GET /` - Main dashboard
- `GET /properties` - Property management page
- `POST /add_property` - Add new property
- `POST /update_property/<id>` - Update property
- `POST /delete_property/<id>` - Delete property
- `GET /check_payments` - Check for recent payments
- `GET /payment_history/<id>` - Get payment history for property
- `GET /send_test_email` - Test email functionality
- `GET /manual_check_overdue` - Manual overdue payment check

## File Structure

```
rentcheck/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── rentcheck.db          # SQLite database (created automatically)
└── templates/
    ├── dashboard.html    # Main dashboard template
    └── properties.html   # Property management template
```

## Security Notes

- The app includes hardcoded API keys and email credentials for demo purposes
- In production, use environment variables for sensitive information
- The database file should be backed up regularly
- Consider implementing user authentication for multi-user environments

## Troubleshooting

### Email Not Working
1. Check your Gmail app password is correct
2. Ensure 2-factor authentication is enabled on Gmail
3. Test with `/send_test_email` endpoint

### Bank Transactions Not Loading
1. Verify Akahu API credentials
2. Check account ID is correct
3. Ensure sufficient API rate limits

### Database Issues
1. Delete `rentcheck.db` to reset database
2. Restart the application to recreate tables
3. Check file permissions on database file

## Support

For issues or questions, check the console output for error messages and ensure all dependencies are installed correctly.