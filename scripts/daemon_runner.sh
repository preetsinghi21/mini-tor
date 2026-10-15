#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

# Clean up any old processes first
pkill -f "build/dir_authority" 2>/dev/null || true
pkill -f "build/relay_node" 2>/dev/null || true
pkill -f "build/dest_server" 2>/dev/null || true
pkill -f "build/onion_client" 2>/dev/null || true
sleep 0.5

# Trap to kill all background children when this runner exits
cleanup() {
    echo "Stopping Mini-Tor daemon processes..."
    kill $PID_DIR $PID_DEST $PID_GUARD $PID_MID $PID_EXIT 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Directory Authority
./build/dir_authority --port 8000 &
PID_DIR=$!

# 2. Destination Target Server
./build/dest_server --port 9090 &
PID_DEST=$!

sleep 0.5

# 3. Relays
./build/relay_node --name Guard-1 --role guard --port 9001 --dir 127.0.0.1:8000 &
PID_GUARD=$!
./build/relay_node --name Middle-1 --role middle --port 9002 --dir 127.0.0.1:8000 &
PID_MID=$!
./build/relay_node --name Exit-1 --role exit --port 9003 --dir 127.0.0.1:8000 &
PID_EXIT=$!

sleep 1

echo "[✓] All nodes started. Starting Onion Client Web Gateway in foreground..."

# 4. Onion Client Web Gateway (Runs in foreground of the daemon)
exec ./build/onion_client --web-port 8080 --dir 127.0.0.1:8000
