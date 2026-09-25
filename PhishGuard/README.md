# PhishGuard — Phishing URL Reporting System

A secure, Flask-based web application for reporting and tracking suspicious
phishing URLs. Users can register, log in, report malicious URLs with a
threat-level classification, and manage their reports through a clean
security-focused dashboard.

> **தமிழ்:** PhishGuard என்பது ஃபிஷிங் URL-களைப் பதிவுசெய்து கண்காணிக்க
> உதவும் ஒரு பாதுகாப்பான வலைப்பயன்பாடு. பயனர்கள் பதிவு செய்து, உள்நுழைந்து,
> சந்தேகத்திற்குரிய URL-களை அச்சுறுத்தல் நிலையுடன் புகாரளிக்கலாம்.

---

## Table of Contents

1. [Project Description](#project-description)
2. [Technologies Used](#technologies-used)
3. [Features](#features)
4. [Project Structure](#project-structure)
5. [Installation & Setup](#installation--setup)
6. [How to Run](#how-to-run)
7. [Screenshots](#screenshots)
8. [Future Improvements](#future-improvements)
9. [License](#license)

---

## Project Description

PhishGuard is a college-project / portfolio-grade phishing URL reporting
platform built with Python and Flask. It demonstrates secure web development
practices including:

- **Password hashing** using Werkzeug's `pbkdf2:sha256` algorithm
- **Session-based authentication** with login-required route protection
- **Parameterized SQL queries** throughout to prevent SQL injection
- **Server-side input validation** on every form field
- **Ownership-based access control** — users can only edit or delete their own
  reports

Users classify each reported URL by **Threat Level** (Low, Medium, High,
Critical) and track its **Status** (Open, Investigating, Resolved, False
Positive). The dashboard provides filtering and sorting across all reports.

### திட்ட விளக்கம் (Tamil)

PhishGuard என்பது Python மற்றும் Flask கொண்டு உருவாக்கப்பட்ட ஒரு பாதுகாப்பான
வலைப்பயன்பாடு. இது பின்வரும் பாதுகாப்பு அம்சங்களைக் கொண்டுள்ளது:

- கடவுச்சொற்கள் பாதுகாப்பாக ஹாஷ் செய்யப்படுகின்றன
- SQL Injection தாக்குதல்களைத் தடுக்க parameterized queries பயன்படுத்தப்படுகின்றன
- அனைத்து படிவங்களிலும் உள்ளீட்டு சரிபார்ப்பு உள்ளது
- பயனர்கள் தங்கள் சொந்த அறிக்கைகளை மட்டுமே திருத்த அல்லது நீக்க முடியும்

---

## Technologies Used

| Technology           | Purpose                              |
| -------------------- | ------------------------------------ |
| **Python 3.10+**     | Backend programming language         |
| **Flask 3.x**        | Web framework                        |
| **MySQL 8.x**        | Relational database                  |
| **XAMPP**            | Local MySQL/Apache stack (Windows)   |
| **Werkzeug**         | Password hashing & security utilities|
| **HTML5**            | Page markup / templates              |
| **CSS3**             | Styling and responsive layout        |
| **Jinja2**           | Flask template engine                |

---

## Features

- **User Registration & Login** — secure password hashing, session management
- **Report Suspicious URLs** — with threat-level classification
- **Threat Levels** — Low, Medium, High, Critical
- **Status Tracking** — Open, Investigating, Resolved, False Positive
- **Dashboard** — view all reports with filter & sort functionality
- **Edit / Delete** — users manage only their own reports
- **Flash Messages** — instant feedback for every action
- **Input Validation** — server-side validation on all forms
- **SQL Injection Protection** — 100% parameterized queries
- **Responsive Design** — works on desktop, tablet, and mobile

### அம்சங்கள் (Tamil)

- பயனர் பதிவு மற்றும் உள்நுழைவு (பாதுகாப்பான கடவுச்சொல் ஹாஷிங்)
- சந்தேகத்திற்குரிய URL-களைப் புகாரளித்தல்
- அச்சுறுத்தல் நிலை வகைப்படுத்தல் (Low, Medium, High, Critical)
- நிலை கண்காணிப்பு (Open, Investigating, Resolved, False Positive)
- டாஷ்போர்டில் அறிக்கைகளை வடிகட்டி வரிசைப்படுத்தல்
- பயனர்கள் தங்கள் சொந்த அறிக்கைகளை மட்டுமே திருத்த/நீக்க முடியும்

---

## Project Structure

```
PhishGuard/
├── app.py                  # Flask application with all routes
├── database.sql            # MySQL schema (users + reports tables)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── .gitignore              # Git ignore rules
├── templates/
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── dashboard.html      # Reports dashboard (filter + sort)
│   ├── add_report.html     # Add new phishing report
│   └── edit_report.html    # Edit existing report
├── static/
│   └── style.css           # All styling (security-focused theme)
└── screenshots/
    ├── login.png           # Login page screenshot
    ├── register.png        # Register page screenshot
    ├── dashboard.png       # Dashboard screenshot
    ├── add_report.png      # Add report screenshot
    └── mysql.png           # MySQL database screenshot
```

---

## Installation & Setup

### Prerequisites

1. **Python 3.10+** — [Download](https://www.python.org/downloads/)
2. **XAMPP** (recommended on Windows) or any MySQL 8.x server —
   [Download](https://www.apachefriends.org/)

### Step 1 — Clone the Repository

```bash
git clone https://github.com/<your-username>/PhishGuard.git
cd PhishGuard
```

### Step 2 — Create & Activate a Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Set Up the MySQL Database

**Option A — Using XAMPP / phpMyAdmin:**

1. Start **Apache** and **MySQL** from the XAMPP Control Panel.
2. Open <http://localhost/phpmyadmin> in your browser.
3. Click the **Import** tab.
4. Choose `database.sql` from the project folder.
5. Click **Go** — the `phishguard` database and both tables will be created.

**Option B — Using the MySQL command line:**

```bash
mysql -u root -p < database.sql
```

This creates:
- **`users`** table — `id, username, email, password_hash, created_at`
- **`reports`** table — `id, user_id, url, threat_level, status, notes,
  created_at, updated_at` (with a foreign key to `users`)

### Step 5 — Configure Database Credentials (if needed)

By default the app connects to `localhost` with user `root` and an empty
password (XAMPP defaults). To override, set environment variables:

```bash
# Windows (PowerShell)
$env:DB_HOST="localhost"
$env:DB_USER="root"
$env:DB_PASSWORD=""
$env:DB_NAME="phishguard"
$env:PHISHGUARD_SECRET_KEY="your-secret-key-here"

# macOS / Linux
export DB_HOST=localhost
export DB_USER=root
export DB_PASSWORD=""
export DB_NAME=phishguard
export PHISHGUARD_SECRET_KEY="your-secret-key-here"
```

---

## How to Run

```bash
python app.py
```

Then open your browser and navigate to:

```
http://127.0.0.1:5000
```

1. **Register** a new account on the Register page.
2. **Log in** with your username and password.
3. **Report a URL** by clicking "Report New URL".
4. **View all reports** on the dashboard — filter by threat level or status.
5. **Edit or Delete** your own reports using the action buttons.

### இயக்கும் முறை (Tamil)

1. `python app.py` என்ற கட்டளையை இயக்கவும்
2. `http://127.0.0.1:5000` என்ற முகவரியை உலாவியில் திறக்கவும்
3. புதிய கணக்கைப் பதிவு செய்து உள்நுழையவும்
4. "Report New URL" பொத்தானைக் கிளிக் செய்து URL புகாரளிக்கவும்
5. டாஷ்போர்டில் அனைத்து அறிக்கைகளையும் காணலாம்

---

## Screenshots

Place the following screenshots in the `screenshots/` folder after running
the application:

| File              | Description                        |
| ----------------- | ---------------------------------- |
| `login.png`       | Login page                         |
| `register.png`    | Registration page                  |
| `dashboard.png`   | Reports dashboard with filter/sort |
| `add_report.png`  | Add new phishing report form       |
| `mysql.png`       | MySQL database tables in phpMyAdmin|

> To capture screenshots: run the app, open each page in your browser, and
> use the screenshot tool (Win+Shift+S on Windows, Cmd+Shift+4 on macOS).

---

## Future Improvements

PhishGuard is designed to be extensible. Planned future enhancements:

1. **AI-Based URL Classification** — automatically predict threat level using
   a machine learning model trained on phishing URL datasets.

2. **Google Safe Browsing API Integration** — check reported URLs against
   Google's Safe Browsing threat database for real-time verification.

3. **Automatic URL Reputation Checking** — query services like VirusTotal,
   URLVoid, or PhishTank to fetch reputation scores on submission.

4. **Admin Role** — add an admin user role with the ability to manage all
   reports, moderate content, and view platform-wide statistics.

5. **Email Notifications** — send email alerts when a report's status changes
   or when a highly-threatened URL is reported.

6. **URL Scanning** — perform automated scans of reported URLs for known
   phishing indicators (suspicious redirects, fake login forms, SSL issues).

### எதிர்கால மேம்பாடுகள் (Tamil)

1. AI அடிப்படையிலான URL வகைப்படுத்தல்
2. Google Safe Browsing API ஒருங்கிணைப்பு
3. தானியங்கி URL நற்பெயர் சரிபார்ப்பு
4. நிர்வாகி (Admin) பங்கு
5. மின்னஞ்சல் அறிவிப்புகள்
6. URL ஸ்கேனிங்

---

## Security Notes

- Passwords are hashed with `pbkdf2:sha256` (Werkzeug) — never stored in plain text.
- All SQL operations use **parameterized queries** (`%s` placeholders) to
  prevent SQL injection.
- Session-based authentication protects all dashboard/report routes.
- Users can only edit or delete reports they own — ownership is checked at the
  database query level (`WHERE user_id = %s`).
- The `SECRET_KEY` should be changed from the default for any deployment.

---

## License

This project is licensed under the **MIT License** — free to use, modify, and
distribute for educational and portfolio purposes.

---

> Built as a college submission project and portfolio piece demonstrating
> secure web development with Python, Flask, and MySQL.
