# Automotive Diagnostic System

A comprehensive web-based diagnostic system for automotive technicians to troubleshoot vehicle issues using Diagnostic Trouble Codes (DTCs).

## Features

- **User Authentication & Authorization**: Role-based access control (Admin, Technician, Viewer)
- **Vehicle Diagnosis**: Input DTC codes and get detailed diagnostic guidance
- **DTC Database**: Comprehensive database of diagnostic trouble codes with:
  - Detailed descriptions
  - Possible causes
  - Step-by-step diagnostic procedures
  - Required tools
- **Diagnostic Logging**: Track all diagnostic sessions with user attribution
- **Web Interface**: Modern, responsive Bootstrap-based UI
- **Multi-User Support**: Concurrent user sessions with permission management

## Quick Start

### Local Development

1. **Clone/Download** the project files
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the application**:
   ```bash
   python app.py
   ```
4. **Access the app** at `http://localhost:5000`
5. **Login** with default credentials:
   - Username: `admin`
   - Password: `admin123`

### Deploy to Render

1. **Push to GitHub**: Upload all files to a GitHub repository
2. **Connect to Render**: 
   - Go to [render.com](https://render.com)
   - Create new Web Service
   - Connect your GitHub repo
3. **Configure**:
   - Environment: Python 3
   - Build Command: (leave blank)
   - Start Command: `gunicorn app:app`
4. **Deploy**: Render will automatically build and deploy your app

## Default Login

- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ Change this password immediately after first login!**

## File Structure

```
automotive-diagnostic-system/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Procfile              # Render deployment config
├── .gitignore            # Git ignore rules
├── README.md             # This file
├── diagnostic_system.db  # SQLite database (auto-created)
└── templates/            # HTML templates
    ├── base.html
    ├── login.html
    ├── dashboard.html
    ├── diagnose.html
    ├── diagnosis_result.html
    └── logs.html
```

## User Roles & Permissions

### Admin
- Full system access
- User management
- All diagnostic functions
- View all logs and reports

### Technician
- Perform diagnostics
- View diagnostic logs
- Cannot manage users

### Viewer
- View diagnostic logs only
- Cannot perform diagnostics
- Cannot manage users

## DTC Database

The system includes common diagnostic trouble codes:

- **P0300**: Random/Multiple Cylinder Misfire
- **P0171**: System Too Lean (Bank 1)
- **P0420**: Catalyst System Efficiency Below Threshold
- And many more...

## Security Features

- Password hashing (SHA-256)
- Session management
- Role-based access control
- SQL injection protection
- CSRF protection (Flask built-in)

## Production Considerations

- Change default admin password
- Set strong `SECRET_KEY` environment variable
- Use PostgreSQL for production (instead of SQLite)
- Enable HTTPS
- Regular database backups
- Monitor user activity

## Support

For issues or questions, please check the code comments or create an issue in the repository.

## License

This project is provided as-is for educational and commercial use.
