"""
PhishGuard - Phishing URL Reporting System
==========================================

A Flask-based web application that lets users register, log in, and report
suspicious phishing URLs with a threat-level classification.  All data is
stored in a MySQL database and every database operation uses parameterized
queries to prevent SQL injection.

Author : PhishGuard Project
License: MIT
"""

import re
import os
from datetime import datetime
from functools import wraps

import mysql.connector
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
# In production this should be loaded from an environment variable.
app.config["SECRET_KEY"] = os.environ.get(
    "PHISHGUARD_SECRET_KEY", "change-this-secret-key-in-production"
)

# Database connection settings (XAMPP / MySQL defaults).
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "phishguard"),
}

# Allowed option sets (server-side validation).
THREAT_LEVELS = ("Low", "Medium", "High", "Critical")
STATUSES = ("Open", "Investigating", "Resolved", "False Positive")

# Basic URL pattern for input validation.
URL_PATTERN = re.compile(
    r"^https?://"
    r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"[A-Z]{2,63}"
    r"(?::\d{1,5})?(?:/[^\s]*)?$",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    """Return a single MySQL connection per request, created lazily."""
    if "db" not in g:
        g.db = mysql.connector.connect(**DB_CONFIG)
    return g.db


@app.teardown_appcontext
def close_db(exc):  # noqa: D401 - Flask signature
    """Close the DB connection at the end of every request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False, commit=False):
    """Run a parameterized query and return rows (or lastrowid on commit)."""
    db = get_db()
    cur = db.cursor(dictionary=True)
    cur.execute(query, args)
    if commit:
        db.commit()
        last_id = cur.lastrowid
        cur.close()
        return last_id
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


# ---------------------------------------------------------------------------
# Authentication decorator
# ---------------------------------------------------------------------------
def login_required(view):
    """Redirect anonymous users to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def validate_username(username):
    """3-20 alphanumeric characters or underscores."""
    return bool(re.match(r"^[A-Za-z0-9_]{3,20}$", username or ""))


def validate_email(email):
    return bool(EMAIL_PATTERN.match(email or ""))


def validate_url(url):
    return bool(URL_PATTERN.match(url or ""))


def validate_password(password):
    """Minimum 8 characters, at least one letter and one number."""
    return bool(re.match(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$", password or ""))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Redirect the landing page to the dashboard or login."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration with hashed passwords."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # --- Server-side validation ---
        if not validate_username(username):
            flash("Username must be 3-20 characters (letters, numbers, underscores).", "danger")
        elif not validate_email(email):
            flash("Please enter a valid email address.", "danger")
        elif not validate_password(password):
            flash("Password must be at least 8 characters with a letter and a number.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            # Check for existing username/email (parameterized).
            existing = query_db(
                "SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1",
                (username, email),
                one=True,
            )
            if existing:
                flash("That username or email is already registered.", "danger")
            else:
                password_hash = generate_password_hash(password, method="pbkdf2:sha256")
                query_db(
                    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                    (username, email, password_hash),
                    commit=True,
                )
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user and start a session."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = query_db(
            "SELECT id, username, password_hash FROM users WHERE username = %s LIMIT 1",
            (username,),
            one=True,
        )
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """End the current session."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """List all reports with optional filtering and sorting."""
    threat = request.args.get("threat", "")
    status = request.args.get("status", "")
    sort = request.args.get("sort", "created_desc")

    # Whitelist sort columns to prevent SQL injection via ORDER BY.
    sort_map = {
        "created_desc": "r.created_at DESC",
        "created_asc": "r.created_at ASC",
        "threat_desc": "FIELD(r.threat_level, 'Critical', 'High', 'Medium', 'Low')",
        "url_asc": "r.url ASC",
    }
    order_by = sort_map.get(sort, "r.created_at DESC")

    # Build a parameterized WHERE clause dynamically.
    conditions = []
    params = []
    if threat in THREAT_LEVELS:
        conditions.append("r.threat_level = %s")
        params.append(threat)
    if status in STATUSES:
        conditions.append("r.status = %s")
        params.append(status)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    # ORDER BY is safe here because order_by comes from a fixed whitelist.
    reports = query_db(
        f"""
        SELECT r.id, r.url, r.threat_level, r.status, r.notes,
               r.created_at, r.updated_at, r.user_id, u.username
        FROM reports r
        JOIN users u ON r.user_id = u.id
        {where}
        ORDER BY {order_by}
        """,
        tuple(params),
    )

    return render_template(
        "dashboard.html",
        reports=reports,
        threat_levels=THREAT_LEVELS,
        statuses=STATUSES,
        current_threat=threat,
        current_status=status,
        current_sort=sort,
    )


@app.route("/report/add", methods=["GET", "POST"])
@login_required
def add_report():
    """Create a new phishing URL report."""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        threat_level = request.form.get("threat_level", "")
        status = request.form.get("status", "Open")
        notes = request.form.get("notes", "").strip()

        if not validate_url(url):
            flash("Please enter a valid URL starting with http:// or https://.", "danger")
        elif threat_level not in THREAT_LEVELS:
            flash("Invalid threat level.", "danger")
        elif status not in STATUSES:
            flash("Invalid status.", "danger")
        elif len(notes) > 1000:
            flash("Notes must be 1000 characters or fewer.", "danger")
        else:
            query_db(
                """INSERT INTO reports
                   (user_id, url, threat_level, status, notes)
                   VALUES (%s, %s, %s, %s, %s)""",
                (session["user_id"], url, threat_level, status, notes),
                commit=True,
            )
            flash("Report submitted successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("add_report.html", threat_levels=THREAT_LEVELS, statuses=STATUSES)


@app.route("/report/edit/<int:report_id>", methods=["GET", "POST"])
@login_required
def edit_report(report_id):
    """Edit a report owned by the current user only."""
    report = query_db(
        "SELECT * FROM reports WHERE id = %s AND user_id = %s LIMIT 1",
        (report_id, session["user_id"]),
        one=True,
    )
    if report is None:
        flash("Report not found or you do not have permission to edit it.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        threat_level = request.form.get("threat_level", "")
        status = request.form.get("status", "")
        notes = request.form.get("notes", "").strip()

        if not validate_url(url):
            flash("Please enter a valid URL starting with http:// or https://.", "danger")
        elif threat_level not in THREAT_LEVELS:
            flash("Invalid threat level.", "danger")
        elif status not in STATUSES:
            flash("Invalid status.", "danger")
        elif len(notes) > 1000:
            flash("Notes must be 1000 characters or fewer.", "danger")
        else:
            query_db(
                """UPDATE reports
                   SET url = %s, threat_level = %s, status = %s, notes = %s,
                       updated_at = %s
                   WHERE id = %s AND user_id = %s""",
                (url, threat_level, status, notes, datetime.now(), report_id, session["user_id"]),
                commit=True,
            )
            flash("Report updated successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template("edit_report.html", report=report, threat_levels=THREAT_LEVELS, statuses=STATUSES)


@app.route("/report/delete/<int:report_id>", methods=["POST"])
@login_required
def delete_report(report_id):
    """Delete a report owned by the current user only."""
    # Ownership is enforced inside the WHERE clause itself.
    result = query_db(
        "DELETE FROM reports WHERE id = %s AND user_id = %s",
        (report_id, session["user_id"]),
        commit=True,
    )
    flash("Report deleted.", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(err):
    return render_template("login.html"), 404


@app.errorhandler(500)
def server_error(err):
    flash("Something went wrong on our end. Please try again.", "danger")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
