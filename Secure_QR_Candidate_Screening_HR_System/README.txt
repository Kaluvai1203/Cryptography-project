SECURE QR-BASED CANDIDATE SCREENING AND HR SCHEDULING SYSTEM
============================================================

REQUIREMENTS
- Windows 10/11
- Python 3.10 or newer
- Internet connection for Bootstrap styling and browser QR scanner library

INSTALLATION (WINDOWS CMD)
1. Extract this ZIP file.
2. Open Command Prompt in the extracted Secure_QR_Candidate_HR folder.
3. Create virtual environment:
   python -m venv .venv
4. Activate:
   .venv\Scripts\activate
5. Install packages:
   pip install -r requirements.txt
6. Run:
   python app.py
7. Open browser:
   http://127.0.0.1:5000

DEMO HR LOGIN
Email: hr@demo.com
Password: HRdemo@123

CANDIDATE
- Register a new account from the Register page.
- Complete your profile and upload documents.
- Browse jobs and apply.
- Generate your QR code from the candidate dashboard.
- HR scans the QR from HR Dashboard > QR Scanner.

IMPLEMENTED
- Candidate registration/login and HR login
- Password hashing
- Candidate personal, address, education, professional and skills profile
- Profile photo upload
- Resume and supporting document upload/download/delete
- Job vacancy listing and HR job management
- Candidate job applications and status tracking
- Secure random QR token with 30-day expiry and revocation on refresh
- HR QR scanner and protected verification page
- Candidate directory and document viewing
- Interview scheduling, rescheduling by creating a new appointment, cancellation
- Basic exact-time conflict detection
- Audit logs
- SQLite database

IMPORTANT LIMITATIONS / BEFORE REAL DEPLOYMENT
- This is a college-project prototype, not a production HR platform.
- Change SECRET_KEY in app.py or set the SECRET_KEY environment variable.
- Use HTTPS, CSRF protection, rate limiting, email OTP, antivirus scanning,
  strict document access policies and production server configuration before deployment.
- Email notification sending is not configured; SMTP integration can be added.
- Resume AI ranking/screening is intentionally not included in this feature set.
- Interview conflict detection currently blocks an exact same datetime; expand it
  to duration-based overlap checks for a production implementation.
- Browser QR scanning needs camera permission and usually HTTPS or localhost.
- Uploaded files are stored locally in the uploads folder.
