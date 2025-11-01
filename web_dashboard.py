import os
import json
import subprocess
import threading
import time
from flask import Flask, request, render_template_string, redirect, url_for, session, abort, flash

# --- متغیرهای اصلی ---
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin" # پسورد پیش‌فرض اولیه
BOT_SERVICE_NAME = "config_bot"
WEB_SERVICE_NAME = "config_bot_web"
ENV_FILE = ".env"
USERS_FILE = "users.json"
ORDERS_FILE = "orders.json"
LOG_LINES_TO_SHOW = 100
PYTHON_PATH = subprocess.getoutput("which python3")
GUNICORN_PATH = subprocess.getoutput("which gunicorn")

app = Flask(__name__)

# --- کدهای HTML ---

HTML_LOGIN = """
<!DOCTYPE html>
<html lang="en" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - hamsell</title>
    <style>
        body { background: #2b2b2b; color: #f0f0f0; font-family: sans-serif; display: grid; place-items: center; min-height: 90vh; }
        .login-box { background: #3c3c3c; border-radius: 8px; padding: 25px; width: 300px; box-shadow: 0 4px 10px rgba(0,0,0,0.4); }
        h2 { text-align: center; color: #4CAF50; margin-top: 0; }
        label { display: block; margin-bottom: 8px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 93%; background: #2b2b2b; color: #f0f0f0; border: 1px solid #555; border-radius: 4px; padding: 10px; }
        button { width: 100%; padding: 10px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 15px; }
        button:hover { background: #45a049; }
        .error { color: #f44336; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>hamsell Dashboard</h2>
        <form method="POST">
            <label for="username">نام کاربری:</label>
            <input type="text" id="username" name="username" required>
            <label for="password" style="margin-top:10px;">رمز عبور:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">ورود</button>
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - hamsell</title>
    <style>
        body { background: #2b2b2b; color: #f0f0f0; font-family: sans-serif; margin: 0; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        .header h1 { color: #4CAF50; margin: 0; }
        .header a { color: #f44336; text-decoration: none; font-weight: bold; }
        .grid-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: #3c3c3c; border-radius: 8px; padding: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.4); }
        .card h2 { margin-top: 0; border-bottom: 1px solid #555; padding-bottom: 10px; }
        .status { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .status-dot { height: 15px; width: 15px; border-radius: 50%; display: inline-block; }
        .status-dot.active { background: #4CAF50; box-shadow: 0 0 10px #4CAF50; }
        .status-dot.inactive { background: #f44336; box-shadow: 0 0 10px #f44336; }
        .status-dot.other { background: #fdd835; }
        .actions { display: flex; gap: 10px; }
        .btn { padding: 8px 12px; text-decoration: none; color: white; border-radius: 4px; cursor: pointer; border: none; font-family: sans-serif; }
        .btn-green { background: #4CAF50; } .btn-green:hover { background: #45a049; }
        .btn-yellow { background: #fdd835; color: #2b2b2b; } .btn-yellow:hover { background: #fbc02d; }
        .btn-red { background: #f44336; } .btn-red:hover { background: #e53935; }
        .btn-blue { background: #2196F3; } .btn-blue:hover { background: #1E88E5; }
        .stats p { font-size: 1.2em; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>hamsell Dashboard</h1>
        <a href="{{ url_for('logout') }}">خروج</a>
    </div>

    <div class="grid-container">
        <div class="card">
            <h2>وضعیت سرویس‌ها</h2>
            <div class="status">
                <span>سرویس ربات (Bot)</span>
                {% if bot_status == 'active' %}
                    <span class="status-dot active" title="Active"></span>
                {% elif bot_status == 'inactive' or bot_status == 'failed' %}
                    <span class="status-dot inactive" title="Inactive/Failed"></span>
                {% else %}
                    <span class="status-dot other" title="{{ bot_status }}"></span>
                {% endif %}
            </div>
            <div class="actions">
                <a href="{{ url_for('control_service', service='bot', action='start') }}" class="btn btn-green">Start</a>
                <a href="{{ url_for('control_service', service='bot', action='stop') }}" class="btn btn-red">Stop</a>
                <a href="{{ url_for('control_service', service='bot', action='restart') }}" class="btn btn-yellow">Restart</a>
            </div>
            <hr style="border-color: #555; margin: 20px 0;">
            <div class="status">
                <span>سرویس داشبورد (Web)</span>
                <span class="status-dot active" title="Active"></span>
            </div>
            <div class="actions">
                <a href="{{ url_for('control_service', service='web', action='restart') }}" class="btn btn-yellow">Restart Web</a>
            </div>
        </div>

        <div class="card stats">
            <h2>آمار کلی</h2>
            <p>کاربران کل: <strong>{{ stats.total_users }}</strong></p>
            <p>سفارشات کل: <strong>{{ stats.total_orders }}</strong></p>
        </div>

        <div class="card">
            <h2>ابزارها</h2>
            <a href="{{ url_for('logs') }}" class="btn btn-blue" style="width: 90%; text-align: center;">مشاهده لاگ‌های ربات</a>
        </div>
    </div>
</body>
</html>
"""

HTML_LOGS = """
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs - hamsell</title>
    <style>
        body { background: #1e1e1e; color: #d4d4d4; font-family: 'Courier New', Courier, monospace; margin: 0; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; margin-bottom: 20px; }
        .header h1 { color: #4CAF50; margin: 0; }
        .header a { color: #2196F3; text-decoration: none; font-weight: bold; }
        .log-container { background: #2b2b2b; border-radius: 8px; padding: 20px; white-space: pre-wrap; line-height: 1.5; font-size: 14px; max-height: 80vh; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Bot Logs</h1>
        <a href="{{ url_for('dashboard') }}">&larr; بازگشت به داشبورد</a>
    </div>
    <div class="log-container">
{{ log_data }}
    </div>
</body>
</html>
"""

HTML_INSTALL = """
<!DOCTYPE html>
<html lang="en" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Install - hamsell</title>
    <style>
        body { background: #2b2b2b; color: #f0f0f0; font-family: sans-serif; display: grid; place-items: center; min-height: 90vh; }
        .install-box { background: #3c3c3c; border-radius: 8px; padding: 25px; width: 400px; box-shadow: 0 4px 10px rgba(0,0,0,0.4); }
        h2 { text-align: center; color: #4CAF50; margin-top: 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; font-size: 0.9em; color: #ccc; }
        input[type="text"], input[type="password"] { width: 95%; background: #2b2b2b; color: #f0f0f0; border: 1px solid #555; border-radius: 4px; padding: 10px; margin-bottom: 10px; }
        button { width: 100%; padding: 12px; background: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; margin-top: 15px; }
        button:hover { background: #45a049; }
        .section { border-bottom: 1px solid #555; padding-bottom: 10px; margin-bottom: 15px; }
        .error { color: #f44336; background: #5a2c2c; padding: 10px; border-radius: 4px; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="install-box">
        <h2>نصب ربات hamsell</h2>
        <p style="text-align: center; color: #ccc; margin-top: -10px;">لاگین پیش‌فرض: (admin / admin)</p>

        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}

        <form method="POST">
            <div class="section">
                <h4>تنظیمات ربات تلگرام</h4>
                <label for="TG_BOT_TOKEN">توکن ربات:</label>
                <input type="text" id="TG_BOT_TOKEN" name="TG_BOT_TOKEN" required>

                <label for="MAIN_ADMIN_ID">آیدی عددی ادمین:</label>
                <input type="text" id="MAIN_ADMIN_ID" name="MAIN_ADMIN_ID" required>

                <label for="YOUR_BRAND_ID">آیدی پشتیبانی (مثال: @hamsell):</label>
                <input type="text" id="YOUR_BRAND_ID" name="YOUR_BRAND_ID" required>
            </div>

            <div class="section">
                <h4>تنظیمات API تلگرام</h4>
                <label for="TG_API_ID">API ID:</label>
                <input type="text" id="TG_API_ID" name="TG_API_ID" required>

                <label for="TG_API_HASH">API Hash:</label>
                <input type="text" id="TG_API_HASH" name="TG_API_HASH" required>
            </div>

            <div class="section">
                <h4>تنظیمات جدید پنل وب</h4>
                <label for="WEB_ADMIN_USER">نام کاربری جدید پنل (پیش‌فرض: admin):</label>
                <input type="text" id="WEB_ADMIN_USER" name="WEB_ADMIN_USER" placeholder="admin">

                <label for="WEB_ADMIN_PASS">رمز عبور جدید پنل:</label>
                <input type="password" id="WEB_ADMIN_PASS" name="WEB_ADMIN_PASS" required>
            </div>

            <button type="submit">نصب و راه‌اندازی نهایی</button>
        </form>
    </div>
</body>
</html>
"""

# --- توابع کمکی ---

def load_env():
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    os.environ[key] = value

def is_installed():
    return os.path.exists(ENV_FILE)

def run_shell_command(command):
    try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True, timeout=15)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip()
    except Exception as e:
        return False, str(e)

def get_service_status(service_name):
    stdout, _ = run_shell_command(f"systemctl is-active {service_name}")
    if not stdout:
        return "not_found"
    return stdout.strip()

def get_bot_logs():
    stdout, stderr = run_shell_command(
        f"journalctl -u {BOT_SERVICE_NAME} -n {LOG_LINES_TO_SHOW} --no-pager"
    )
    if stderr:
        return f"Error reading logs: {stderr}"
    return stdout or "No logs found."

def get_stats():
    try:
        with open(USERS_FILE, "r") as f:
            total_users = len(json.load(f))
    except Exception:
        total_users = "N/A"

    try:
        with open(ORDERS_FILE, "r") as f:
            total_orders = len(json.load(f))
    except Exception:
        total_orders = "N/A"

    return {
        "total_users": total_users,
        "total_orders": total_orders,
    }

def create_systemd_services(env_data):
    project_path = os.path.dirname(os.path.abspath(__file__))

    bot_service_content = f"""
[Unit]
Description=hamsell Telegram Bot Service
After=network.target

[Service]
User=root
WorkingDirectory={project_path}
EnvironmentFile={project_path}/{ENV_FILE}
ExecStart={PYTHON_PATH} -u bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

    web_service_content = f"""
[Unit]
Description=hamsell Web Dashboard Service
After=network.target

[Service]
User=root
WorkingDirectory={project_path}
EnvironmentFile={project_path}/{ENV_FILE}
ExecStart={GUNICORN_PATH} --workers 4 --bind 0.0.0.0:5000 "web_dashboard:app"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

    try:
        with open(f"/etc/systemd/system/{BOT_SERVICE_NAME}.service", "w") as f:
            f.write(bot_service_content)

        with open(f"/etc/systemd/system/{WEB_SERVICE_NAME}.service", "w") as f:
            f.write(web_service_content)

        return True, None
    except Exception as e:
        return False, f"خطا در ساخت فایل سرویس: {e}"

# --- بارگذاری اولیه ---
load_env()
app.secret_key = os.getenv("WEB_SECRET_KEY", "temp_secret_key_for_install")

# --- صفحات وب (Routings) ---

@app.before_request
def check_install_and_login():
    if request.path == '/install' or request.path.startswith('/static'):
        return

    if not is_installed():
        return redirect(url_for('install'))

    # بارگذاری مجدد .env برای گرفتن آپدیت‌ها
    load_env()

    if request.path != '/login' and not session.get('logged_in'):
        return redirect(url_for('login'))

@app.route("/install", methods=["GET", "POST"])
def install():
    if is_installed():
        return redirect(url_for('login'))

    auth = request.authorization
    if not auth or auth.username != DEFAULT_USERNAME or auth.password != DEFAULT_PASSWORD:
        return 'Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

    if request.method == "POST":
        env_data = request.form.to_dict()

        if not env_data.get("WEB_ADMIN_USER"):
            env_data["WEB_ADMIN_USER"] = "admin"
        if not env_data.get("WEB_ADMIN_PASS"):
            return render_template_string(HTML_INSTALL, error="رمز عبور پنل وب الزامی است")

        env_data["WEB_SECRET_KEY"] = os.urandom(16).hex()

        try:
            with open(ENV_FILE, "w") as f:
                for key, value in env_data.items():
                    f.write(f"{key}={value}\n")
        except Exception as e:
            return render_template_string(HTML_INSTALL, error=f"خطا در نوشتن فایل .env: {e}")

        success, error = create_systemd_services(env_data)
        if not success:
            return render_template_string(HTML_INSTALL, error=error)

        run_shell_command("systemctl daemon-reload")
        run_shell_command(f"systemctl enable {BOT_SERVICE_NAME}")
        run_shell_command(f"systemctl enable {WEB_SERVICE_NAME}")
        run_shell_command(f"systemctl start {BOT_SERVICE_NAME}")

        # ریستارت کردن سرویس وب در یک ترد جداگانه تا خودکشی نکند
        def restart_web_service():
            time.sleep(1) # یک ثانیه تاخیر تا پاسخ به مرورگر ارسال شود
            run_shell_command(f"systemctl restart {WEB_SERVICE_NAME}")

        threading.Thread(target=restart_web_service).start()

        return "نصب با موفقیت انجام شد! در حال ریستارت کردن پنل وب و انتقال به صفحه لاگین..." + \
               "<meta http-equiv='refresh' content='5;url=/' />"

    return render_template_string(HTML_INSTALL)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        ADMIN_USERNAME = os.getenv("WEB_ADMIN_USER", DEFAULT_USERNAME)
        ADMIN_PASSWORD = os.getenv("WEB_ADMIN_PASS", DEFAULT_PASSWORD)

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template_string(HTML_LOGIN, error="نام کاربری یا رمز عبور اشتباه است")
    return render_template_string(HTML_LOGIN)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
def dashboard():
    bot_status = get_service_status(BOT_SERVICE_NAME)
    web_status = get_service_status(WEB_SERVICE_NAME)
    stats = get_stats()

    return render_template_string(HTML_DASHBOARD, 
                                  bot_status=bot_status, 
                                  web_status=web_status, 
                                  stats=stats)

@app.route("/logs")
def logs():
    log_data = get_bot_logs()
    return render_template_string(HTML_LOGS, log_data=log_data)

@app.route("/control/<service>/<action>")
def control_service(service, action):
    if not session.get('logged_in'):
        abort(403) 

    if service == "bot":
        service_name = BOT_SERVICE_NAME
    elif service == "web":
        service_name = WEB_SERVICE_NAME
    else:
        return "Invalid service", 400

    if action not in ["start", "stop", "restart"]:
        return "Invalid action", 400

    _, stderr = run_shell_command(f"systemctl {action} {service_name}")
    if stderr:
        # flash() requires template rendering, redirecting is simpler
        print(f"Error executing action: {stderr}")

    return redirect(url_for("dashboard"))

# --- اجرای برنامه ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)