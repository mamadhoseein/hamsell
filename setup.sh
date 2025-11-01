#!/bin/bash

# ================================================
#       Hamsell Management CLI Tool
# ------------------------------------------------
# Designed for simple execution without "sudo hamsell"
# ================================================

# --- Configuration ---
GIT_REPO_URL="https://github.com/mamadhoseein/hamsell.git"
PROJECT_DIR="hamsell"
VENV_DIR="myenv"
WEB_SERVICE_NAME="config_bot_web"
BOT_SERVICE_NAME="config_bot"

# Project root path (Moved to /opt/ for better system compatibility)
PROJECT_ROOT="/opt" 
PROJECT_PATH="${PROJECT_ROOT}/${PROJECT_DIR}"
VENV_PATH="${PROJECT_PATH}/${VENV_DIR}"
PYTHON_PATH="${VENV_PATH}/bin/python3"

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
BLUE="\033[0;34m"
NC="\033[0m"

# --- Helper Functions ---

# (تغییر ۱: ترفند پاکسازی)
# به جای پاک کردن، ۱۰۰ خط خالی چاپ می‌کنیم تا پیام‌های قبلی از صفحه خارج شوند
clear_all() {
    printf '\n%.0s' {1..100}
}

# (تغییر ۲: تابع توقف)
# منتظر می‌ماند تا کاربر Enter را بزند و سپس به منو برمی‌گردد
# این جلوی "اسپم شدن" منو را می‌گیرد
pause_for_user() {
    echo -e "\n${YELLOW}Press [Enter] to return to the menu...${NC}"
    read
}

# ------------------------------------------------
# Main Service Control Functions (Requires SUDO internal)
# ------------------------------------------------

control_service() {
    local SERVICE=$1
    local ACTION=$2
    local SERVICE_NAME=""
    local DISPLAY_NAME=""

    case "$SERVICE" in
        bot) SERVICE_NAME="${BOT_SERVICE_NAME}.service"; DISPLAY_NAME="Telegram Bot";;
        web) SERVICE_NAME="${WEB_SERVICE_NAME}.service"; DISPLAY_NAME="Web Panel";;
        *) echo -e "${RED}Error: Invalid service!${NC}"; return 1;;
    esac

    echo -e "${YELLOW}⚙️ Executing [${ACTION}] on ${DISPLAY_NAME}...${NC}"
    # اجرای systemctl با sudo داخلی برای کاربر نهایی
    sudo systemctl "$ACTION" "$SERVICE_NAME" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ ${DISPLAY_NAME} successfully ${ACTION}ed.${NC}"
    else
        echo -e "${RED}❌ Failed! Checking status...${NC}"
        # استفاده از systemctl بدون sudo برای نمایش status
        systemctl status "$SERVICE_NAME" --no-pager -n 5
    fi
}

# ------------------------------------------------
# Dependency Management Function (Includes Pillow)
# ------------------------------------------------

install_deps() {
    echo -e "${YELLOW}🐍 Setting up Python Virtual Environment and Dependencies...${NC}"
    
    cd "${PROJECT_PATH}" || { echo -e "${RED}Error: Project directory not found at ${PROJECT_PATH}${NC}"; return 1; }
    
    if [ ! -d "$VENV_PATH" ]; then
        echo -e "${YELLOW}Virtual environment not found. Creating it now.${NC}"
        # اجرای ساخت VENV با sudo چون پوشه پروژه در /opt/ است
        sudo python3 -m venv "${VENV_PATH}"
    fi

    # اجرای دستورات در یک subshell با دسترسی venv
    (
        source "${VENV_PATH}/bin/activate"
        echo -e "${CYAN}Installing core dependencies...${NC}"
        
        # Direct Installation of all packages including Pillow
        pip install -q --upgrade pip
        pip install -q gunicorn flask qrcode requests routeros_api pyrogram TgCrypto Pillow || {
            echo -e "${RED}❌ FATAL ERROR: Failed to install Python packages!${NC}";
            deactivate
            return 1
        }
        
        deactivate
    )

    echo -e "${GREEN}✅ All Python dependencies successfully installed.${NC}"

    # Reload and Restart Web Service to apply changes
    echo -e "${CYAN}Applying changes and restarting Web Panel...${NC}"
    sudo systemctl daemon-reload
    sudo systemctl restart ${WEB_SERVICE_NAME}.service

    echo -e "${GREEN}✅ Dependencies installed and Web Panel restarted.${NC}"
}

# ------------------------------------------------
# Core Application Functions
# ------------------------------------------------

update_app() {
    echo -e "${YELLOW}🔄 Starting application code update...${NC}"
    cd "${PROJECT_PATH}" || { echo -e "${RED}Error: Project directory not found!${NC}"; return 1; }

    control_service bot stop
    control_service web stop

    echo -e "${CYAN}2. Pulling latest code from Git...${NC}"
    # اجرای git pull با sudo چون پروژه در /opt/ است
    sudo git pull origin main

    install_deps # Update dependencies

    control_service bot restart
    control_service web restart

    echo -e "${GREEN}🎉 Update complete. ${NC}"
}

install() {
    # Check if git clone should be executed or if the project already exists
    if [ -e "$PROJECT_PATH" ]; then
        echo -e "${YELLOW}Project folder already exists. Running cleanup first.${NC}"
        cleanup
    fi

    echo -e "${YELLOW}🚀 1. Installing server dependencies...${NC}"
    # اجرای apt با sudo
    sudo apt update > /dev/null 2>&1
    sudo apt install -y python3 python3-pip python3-venv git > /dev/null 2>&1

    echo -e "${YELLOW}📥 2. Cloning project from Git...${NC}"
    cd "${PROJECT_ROOT}" || exit
    
    # اجرای git clone با sudo و تغییر مالکیت
    sudo git clone "$GIT_REPO_URL" || { echo -e "${RED}Error cloning project!${NC}"; exit 1; }
    # تنظیم مالکیت برای root برای اجرای systemd
    sudo chown -R root:root "${PROJECT_PATH}"
    
    # 3. Install Dependencies in VENV
    install_deps || { exit 1; }

    echo -e "${YELLOW}⚙️ 4. Deploying Web Installer Service...${NC}"

    # Use the Python path of the newly installed VENV (This is now /opt/hamsell/myenv/...)
    cat > /etc/systemd/system/${WEB_SERVICE_NAME}.service << EOL
[Unit]
Description=hamsell Web Installer
After=network.target

[Service]
User=root
WorkingDirectory=${PROJECT_PATH}
ExecStart=${PYTHON_PATH} -m gunicorn --workers 1 --bind 0.0.0.0:5000 "web_dashboard:app"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOL
    
    # daemon-reload and web restart is handled by install_deps function.

    IP_ADDR=$(hostname -I | awk '{print $1}' | head -n 1)

    echo
    echo -e "${GREEN}🎉 Initial Setup Complete!${NC}"
    echo -e "Please open your browser and navigate to:"
    echo
    echo -e "  ${YELLOW}http://${IP_ADDR}:5000/install${NC}"
    echo
    echo -e "Use default admin/admin credentials for the *first* login."
}

cleanup() {
    echo -e "${RED}🛑 Starting Cleanup Process...${NC}"

    # 1. Stop and remove systemd services
    echo -e "${RED}1. Stopping and removing systemd services...${NC}"
    control_service web stop
    control_service bot stop
    
    sudo rm -f /etc/systemd/system/${WEB_SERVICE_NAME}.service
    sudo rm -f /etc/systemd/system/${BOT_SERVICE_NAME}.service
    sudo systemctl daemon-reload

    # 2. Remove project folder
    echo -e "${RED}2. Removing project folder and virtual environment...${NC}"
    # حذف با sudo چون در /opt/ است.
    sudo rm -rf "${PROJECT_PATH}"
    
    echo -e "${GREEN}✅ Cleanup complete.${NC}"
}


# ------------------------------------------------
# Main Menu Logic
# ------------------------------------------------
main_menu() {
    # اتوماتیک پاکسازی (هل دادن به بالا)
    clear_all 
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${CYAN} 🤖 Hamsell CLI Management Tool 🤖 ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "   ${GREEN}1${NC}) 🚀 ${CYAN}Full Install${NC} (From Scratch)"
    echo -e "   ${GREEN}2${NC}) 📦 ${CYAN}Install Dependencies${NC} (Fix missing modules)"
    echo -e "   ${GREEN}3${NC}) 🔄 ${CYAN}Update Project Code${NC} (Pull & Restart)"
    echo -e "   ${GREEN}4${NC}) 🔄 ${CYAN}Restart All Services${NC}"
    echo -e "   ${GREEN}5${NC}) ⚙️ ${CYAN}Check Service Status${NC}"
    echo -e "   ${GREEN}6${NC}) 🛑 ${CYAN}Stop All Services${NC}"
    echo -e "   ${RED}7${NC}) 🗑️ ${RED}Cleanup Project${NC} (Delete All)"
    echo -e "   ${GREEN}0${NC}) Exit"
    echo -e "${BLUE}========================================${NC}"
  t read -rp "Enter your choice: " CHOICE

    # پاکسازی قبل از هر دستور
m   case "$CHOICE" in
        1) 
            clear_all
            install 
            pause_for_user # <--- توقف اتوماتیک
            ;;
        2) 
            clear_all
            install_deps 
            pause_for_user # <--- توقف اتوماتیک
            ;;
        3) 
            clear_all
            update_app 
            pause_for_user # <--- توقف اتوماتیک
            ;;
        4) 
            clear_all
            control_service bot restart
            control_service web restart
            pause_for_user # <--- توقف اتوماتیک
            ;;
        5) 
            clear_all
            systemctl status ${BOT_SERVICE_NAME}.service --no-pager -n 5
            systemctl status ${WEB_SERVICE_NAME}.service --no-pager -n 5
            pause_for_user # <--- توقف اتوماتیک
            ;;
        6) 
            clear_all
            control_service bot stop
            control_service web stop
            pause_for_user # <--- توقف اتوماتیک
            ;;
        7) 
            clear_all
ar         read -rp "⚠️ Are you sure you want to delete everything? (yes/no): " CONFIRM
            if [[ "$CONFIRM" == "yes" ]]; then
                cleanup
            else
                echo -e "${YELLOW}Cleanup operation cancelled.${NC}"
            fi
            pause_for_user # <--- توقف اتوماتیک
            ;;
        0) 
            clear_all
            exit 0 
            ;;
        *) 
            clear_all
            echo -e "${RED}Invalid option!${NC}"
            pause_for_user # <--- توقف اتوماتیک
            ;;
    esac
    main_menu
}

# ------------------------------------------------
# Execution Entry Point
# ------------------------------------------------

main_menu
