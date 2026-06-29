from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import bcrypt
import random

app = Flask(__name__)
app.secret_key = "super_secret_key"

# -------- DATABASE SETUP --------
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            otp INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

# -------- SIMPLE HTML TEMPLATES --------
register_html = """
<h2>Register</h2>
<form method="post">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit">
</form>
<p>{{msg}}</p>
<a href="/login">Login</a>
"""

login_html = """
<h2>Login</h2>
<form method="post">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit">
</form>
<p>{{msg}}</p>
"""

dashboard_html = """
<h2>Welcome {{user}}</h2>
<a href="/logout">Logout</a>
"""

otp_html = """
<h2>Enter OTP</h2>
<form method="post">
OTP: <input name="otp"><br>
<input type="submit">
</form>
<p>{{msg}}</p>
"""

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        # Input validation
        if len(username) < 3 or len(password) < 6:
            msg = "Invalid input! Username >=3 chars, Password >=6 chars"
            return render_template_string(register_html, msg=msg)

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed))
            conn.commit()
            conn.close()
            msg = "Registered successfully!"
        except:
            msg = "Username already exists!"

    return render_template_string(register_html, msg=msg)


# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user[0]):
            # Generate OTP (2FA)
            otp = random.randint(100000, 999999)

            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("UPDATE users SET otp=? WHERE username=?",
                      (otp, username))
            conn.commit()
            conn.close()

            # For demo: print OTP in console
            print(f"[DEBUG] OTP for {username}: {otp}")

            session['temp_user'] = username
            return redirect(url_for("verify_otp"))
        else:
            msg = "Invalid credentials!"

    return render_template_string(login_html, msg=msg)


# -------- VERIFY OTP (2FA) --------
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    msg = ""
    if "temp_user" not in session:
        return redirect("/login")

    if request.method == "POST":
        entered_otp = request.form["otp"]

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT otp FROM users WHERE username=?",
                  (session['temp_user'],))
        real_otp = c.fetchone()
        conn.close()

        if real_otp and str(real_otp[0]) == entered_otp:
            session['user'] = session['temp_user']
            session.pop('temp_user', None)
            return redirect("/dashboard")
        else:
            msg = "Invalid OTP!"

    return render_template_string(otp_html, msg=msg)


# -------- DASHBOARD --------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return render_template_string(dashboard_html, user=session['user'])


# -------- LOGOUT --------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# -------- RUN APP --------
if __name__ == "__main__":
    app.run(debug=True)
