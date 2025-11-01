#!/bin/bash

# ================================================
#       Hamsell Bot Installer & Cleanup Script
# ------------------------------------------------
# این اسکریپت نصب و حذف کامل را به صورت خودکار انجام می‌دهد و 
# مسیرهای VENV را به صورت پویا برای systemd تنظیم می‌کند.
# ================================================

GIT_REPO_URL="https://github.com/mamadhoseein/hamsell.git"
PROJECT_DIR="hamsell"
VENV_DIR="myenv"
WEB_SERVICE_NAME="config_bot_web"
BOT_SERVICE_NAME="config_bot"

# مسیرها به صورت پویا ساخته می‌شوند
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_PATH="${SCRIPT_DIR}/${PROJECT_DIR}"
VENV_PATH="${PROJECT_PATH}/${VENV_DIR}"
PYTHON_PATH="${VENV_PATH}/bin/python3" # مسیر پایتون VENV

# تنظیم رنگ‌ها
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
NC="\033[0m"

# ------------------------------------------------
# تابع حذف کامل (CLEANUP)
# ------------------------------------------------
cleanup() {
    echo -e "${RED}🛑 شروع فرآیند حذف کامل (Cleanup)...${NC}"

    # 1. توقف و حذف سرویس‌های systemd
    echo -e "${RED}1. توقف و حذف سرویس‌های systemd...${NC}"
    systemctl stop ${WEB_SERVICE_NAME}.service > /dev/null 2>&1
    systemctl disable ${WEB_SERVICE_NAME}.service > /dev/null 2>&1
    systemctl stop ${BOT_SERVICE_NAME}.service > /dev/null 2>&1
    systemctl disable ${BOT_SERVICE_NAME}.service > /dev/null 2>&1
    
    rm -f /etc/systemd/system/${WEB_SERVICE_NAME}.service
    rm -f /etc/systemd/system/${BOT_SERVICE_NAME}.service
    systemctl daemon-reload

    # 2. حذف پوشه پروژه
    echo -e "${RED}2. حذف پوشه پروژه و محیط مجازی...${NC}"
    rm -rf "${PROJECT_DIR}"
    rm -rf "${VENV_DIR}"

    echo -e "${GREEN}✅ حذف کامل پروژه انجام شد.${NC}"
}

# ------------------------------------------------
# تابع نصب (INSTALL)
# ------------------------------------------------
install() {
    echo -e "${YELLOW}🚀 1. نصب پیش‌نیازهای سرور...${NC}"
    apt update > /dev/null 2>&1
    apt install -y python3 python3-pip python3-venv git > /dev/null 2>&1

    echo -e "${YELLOW}📥 2. شبیه‌سازی (Cloning) پروژه از Git...${NC}"
    cd "${SCRIPT_DIR}" || exit
    
    if [ -e "$PROJECT_DIR" ]; then 
        echo -e "${YELLOW}پوشه پروژه موجود است. حذف می‌شود.${NC}"
        rm -rf "$PROJECT_DIR"
    fi
    git clone "$GIT_REPO_URL" || { echo -e "${RED}خطا در شبیه‌سازی پروژه!${NC}"; exit 1; }
    cd "$PROJECT_DIR" || exit

    echo -e "${YELLOW}🐍 3. ساخت محیط مجازی و نصب قطعی پکیج‌ها...${NC}"
    
    # ساخت محیط مجازی
    python3 -m venv "${VENV_PATH}"
    
    # افزودن gunicorn و flask برای اطمینان در مرحله اول نصب
    # اگرچه بهتر است اینها در requirements.txt باشند.
    echo -e "\nflask\ngunicorn" >> requirements.txt
    
    source "${VENV_PATH}/bin/activate"
    pip install -q --upgrade pip
    
    # نصب کامل با آپشن‌های مطمئن برای پوشش دادن خطاها
    pip install -q --ignore-installed -r requirements.txt || { echo -e "${RED}خطا در نصب پکیج‌ها!${NC}"; exit 1; }
    deactivate

    echo -e "${YELLOW}⚙️ 4. راه‌اندازی سرویس نصب‌کننده وب (Web Installer)...${NC}"

    # --- ساخت فایل سرویس با مسیر پویا (حل نهایی مشکل 203/EXEC) ---
    cat > /etc/systemd/system/${WEB_SERVICE_NAME}.service << EOL
[Unit]
Description=hamsell Web Installer
After=network.target

[Service]
User=root
WorkingDirectory=${PROJECT_PATH}
# استفاده از مسیر پایتون VENV ساخته شده (به صورت خودکار و پویا)
ExecStart=${PYTHON_PATH} -m gunicorn --workers 1 --bind 0.0.0.0:5000 "web_dashboard:app"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL

    systemctl daemon-reload
    systemctl enable ${WEB_SERVICE_NAME}.service > /dev/null 2>&1
    systemctl restart ${WEB_SERVICE_NAME}.service

    IP_ADDR=$(hostname -I | awk '{print $1}' | head -n 1)

    echo
    echo -e "${GREEN}🎉 نصب اولیه کامل شد!${NC}"
    echo -e "لطفاً مرورگر خود را باز کرده و به آدرس زیر بروید:"
    echo
    echo -e "  ${YELLOW}http://${IP_ADDR}:5000/install${NC}"
    echo
    echo -e "برای لاگین *اولیه* از این اطلاعات استفاده کنید:"
    echo -e "  نام کاربری: ${CYAN}admin${NC}"
    echo -e "  رمز عبور: ${CYAN}admin${NC}"
    echo
    echo -e "دستورالعمل‌های روی صفحه را برای تکمیل نصب دنبال کنید."
}

# ------------------------------------------------
# منطق اجرای اسکریپت
# ------------------------------------------------

case "$1" in
    install)
        install
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo -e "${YELLOW}نحوه استفاده:${NC}"
        echo -e "  ${CYAN}$0 install${NC} - برای نصب و راه‌اندازی اولیه"
        echo -e "  ${CYAN}$0 cleanup${NC} - برای حذف کامل پروژه و سرویس‌ها"
        exit 1
esac
