from flask import Flask, request, render_template, redirect, session, url_for
import sqlite3, psutil
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'kunci_rahasia_enterprise_jing'

def init_db():
    conn = sqlite3.connect('database.db')
    conn.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS logs (username TEXT, status TEXT, waktu DATETIME, ip TEXT)')
    conn.commit(); conn.close()

@app.route('/')
def home():
    if 'user' in session:
        ram = psutil.virtual_memory().percent
        conn = sqlite3.connect('database.db')
        attacks = conn.execute("SELECT COUNT(*) FROM logs WHERE status = 'FAILED'").fetchone()[0]
        conn.close()
        return render_template('dashboard.html', user=session['user'], attacks=attacks, ram_usage=ram)
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    user, pw = request.form.get('user'), request.form.get('pw')
    conn = sqlite3.connect('database.db')
    res = conn.execute("SELECT password FROM users WHERE username = ?", (user,)).fetchone()
    if res and check_password_hash(res[0], pw):
        session['user'] = user
        conn.execute("INSERT INTO logs VALUES (?, 'SUCCESS', ?, ?)", (user, datetime.now(), request.remote_addr))
        conn.commit(); conn.close()
        return redirect('/')
    conn.execute("INSERT INTO logs VALUES (?, 'FAILED', ?, ?)", (user or "Unknown", datetime.now(), request.remote_addr))
    conn.commit(); conn.close()
    return "<h1>Akses Ditolak Jing!</h1><a href='/'>Balik</a>"

@app.route('/admin_logs')
def admin_logs():
    if 'user' not in session: return redirect('/')
    search = request.args.get('q', '')
    conn = sqlite3.connect('database.db')
    if search:
        logs = conn.execute("SELECT * FROM logs WHERE username LIKE ? ORDER BY waktu DESC", ('%'+search+'%',)).fetchall()
    else:
        logs = conn.execute("SELECT * FROM logs ORDER BY waktu DESC LIMIT 50").fetchall()
    conn.close()
    return render_template('admin_logs.html', logs=logs, query=search)

@app.route('/register_page')
def register_page(): return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    user, pw = request.form.get('new_user'), request.form.get('new_pw')
    if user and pw:
        h = generate_password_hash(pw)
        conn = sqlite3.connect('database.db')
        conn.execute("INSERT INTO users VALUES (?, ?)", (user, h))
        conn.commit(); conn.close()
        return redirect('/')
    return "Lengkapi data su!"

@app.route('/logout')
def logout():
    session.pop('user', None); return redirect('/')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080)
