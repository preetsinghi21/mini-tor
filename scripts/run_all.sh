#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "=========================================================="
echo "    STARTING MINI-TOR ONION ROUTING NETWORK (C++)         "
echo "=========================================================="

# Ensure binaries exist
if [ ! -f "build/dir_authority" ] || [ ! -f "build/relay_node" ] || [ ! -f "build/dest_server" ] || [ ! -f "build/onion_client" ]; then
    echo "[!] Binaries missing. Compiling with make..."
    make -j4
fi

# Clean up any lingering processes
"$DIR/scripts/stop_all.sh" > /dev/null 2>&1 || true
sleep 0.5

# 1. Start Directory Authority (Port 8000)
nohup ./build/dir_authority --port 8000 > dir_authority.log 2>&1 &
PID_DIR=$!
echo "[+] Directory Authority started on http://127.0.0.1:8000 (PID: $PID_DIR)"

# 2. Start Destination Target Server (Port 9090)
nohup ./build/dest_server --port 9090 > dest_server.log 2>&1 &
PID_DEST=$!
echo "[+] Destination Target Server started on port 9090 (PID: $PID_DEST)"

sleep 0.5

# 3. Start 3 Relay Nodes (Guard, Middle, Exit)
nohup ./build/relay_node --name Guard-1 --role guard --port 9001 --dir 127.0.0.1:8000 > relay_guard.log 2>&1 &
PID_GUARD=$!
echo "[+] Guard Relay Node started on port 9001 (PID: $PID_GUARD)"

nohup ./build/relay_node --name Middle-1 --role middle --port 9002 --dir 127.0.0.1:8000 > relay_middle.log 2>&1 &
PID_MID=$!
echo "[+] Middle Relay Node started on port 9002 (PID: $PID_MID)"

nohup ./build/relay_node --name Exit-1 --role exit --port 9003 --dir 127.0.0.1:8000 > relay_exit.log 2>&1 &
PID_EXIT=$!
echo "[+] Exit Relay Node started on port 9003 (PID: $PID_EXIT)"

sleep 1

# 4. Start Onion Client & Live Web Gateway (Port 8080)
nohup ./build/onion_client --web-port 8080 --dir 127.0.0.1:8000 > onion_client.log 2>&1 &
PID_CLI=$!
echo "[+] Onion Client & Web Gateway started on http://127.0.0.1:8080 (PID: $PID_CLI)"

echo ""
echo "=========================================================="
echo "   MINI-TOR NETWORK IS READY & RUNNING!                   "
echo "   Web Dashboard:  http://127.0.0.1:8080                  "
echo "   Directory API:  http://127.0.0.1:8000/consensus        "
echo "   Target Server:  http://127.0.0.1:9090                  "
echo "=========================================================="
echo "To view live logs in terminal:"
echo "  tail -f relay_guard.log relay_middle.log relay_exit.log dest_server.log"
echo "To stop the entire network:"
echo "  ./scripts/stop_all.sh"
echo "=========================================================="
