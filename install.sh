#!/usr/bin/env bash

# ==============================================
# 🔧 Installer for YouTube - Helper
# ✅ Supports Termux and Linux (Debian/Ubuntu)
# ==============================================

set -e  # exit on error

# --------- Functions ---------

show_banner() {
  clear
  echo "=========================================="
  echo "🛠️  YouTube - Helper"
  echo "✅ Compatible with: Termux, Ubuntu, Debian"
  echo "📦 Installing dependencies..."
  echo "=========================================="
}

install_python_linux() {
  echo "🧪 Checking & installing Python & pip (Linux)..."
  sudo apt update
  sudo apt install -y python3 python3-pip
}

install_python_termux() {
  echo "📱 Installing Python & pip (Termux)..."
  pkg update -y
  pkg install -y python
}

install_dependencies() {
  echo "📦 Installing required Python packages..."
  pip install --upgrade pip
  pip install rich requests flask
}

get_public_ip() {
  echo "🌐 Fetching public IP..."
  IP=$(curl -s https://api.ipify.org)
  echo "Your public IP: $IP"
}

check_python() {
  echo "🐍 Python version:"
  python3 --version
  pip --version
}

# --------- Start Script ---------

show_banner

# Detect environment
if [[ "$PREFIX" == *"com.termux"* ]]; then
  echo "📱 Detected Termux environment"
  install_python_termux
else
  echo "💻 Detected Linux environment"
  install_python_linux
fi

install_dependencies
check_python

read -p "🧪 Tampilkan IP publik? (y/n): " ip_choice
if [[ "$ip_choice" == "y" ]]; then
  get_public_ip
fi

echo -e "\n✅ [DONE] Semua paket terinstal.\n📁 Jalankan tool dengan: python3 nama_file.py\n"
