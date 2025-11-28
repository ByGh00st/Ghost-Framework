#!/bin/bash

# Chimera Honeypot v3.2 Launcher
# ===============================

echo "=========================================="
echo "  Chimera Hardened Honeypot v3.2"
echo "  ByGhost - Advanced Deception Framework"
echo "=========================================="
echo ""

# Check if honeypot.py exists
if [ ! -f "honeypot.py" ]; then
    echo "❌ Error: honeypot.py not found!"
    echo "Make sure you're in the correct directory."
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1)
echo "🐍 Using: $python_version"

# Check required packages
echo "📦 Checking dependencies..."
python3 -c "import rich, readchar" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Warning: Some dependencies might be missing."
    echo "   Run: pip3 install rich readchar"
fi

echo ""
echo "🚀 Starting honeypot services..."
echo "   • Web Server: http://localhost:8080"
echo "   • SSH Server: localhost:2222"
echo "   • FTP Server: localhost:2121"
echo "   • SMB Server: localhost:14445"
echo "   • SMTP Server: localhost:2525"
echo "   • Redis Server: localhost:16379"
echo "   • ElasticSearch: localhost:9209"
echo ""
echo "📊 Logs will be saved to:"
echo "   • chimera_v3_activity.jsonl"
echo "   • pcap_logs/ (network logs)"
echo "   • siem_events/ (SIEM events)"
echo ""
echo "⚠️  WARNING: This is a real honeypot!"
echo "   It will respond to network connections."
echo "   Press Ctrl+C to stop all services."
echo ""
echo "=========================================="

# Start the honeypot
python3 honeypot.py

echo ""
echo "✅ Honeypot stopped."
