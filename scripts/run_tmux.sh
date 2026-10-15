#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

SESSION="minitor"

# Kill existing session if present
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Clean up any old running processes
"$DIR/scripts/stop_all.sh" > /dev/null 2>&1 || true
sleep 0.5

echo "[+] Launching Mini-Tor 6-Pane Terminal Dashboard in tmux..."

# Create session with full HD terminal geometry (220 columns x 55 lines)
tmux new-session -d -s "$SESSION" -n "Mini-Tor" -x 220 -y 55
tmux set -g mouse on

# 1. Directory Authority (Pane 0)
tmux send-keys -t "$SESSION:0.0" "cd '$DIR' && ./build/dir_authority --port 8000" C-m

# 2. Guard Relay (Pane 1)
tmux split-window -t "$SESSION:0"
tmux select-layout -t "$SESSION:0" tiled
tmux send-keys -t "$SESSION:0.1" "cd '$DIR' && sleep 0.5 && ./build/relay_node --name Guard-1 --role guard --port 9001 --dir 127.0.0.1:8000" C-m

# 3. Middle Relay (Pane 2)
tmux split-window -t "$SESSION:0"
tmux select-layout -t "$SESSION:0" tiled
tmux send-keys -t "$SESSION:0.2" "cd '$DIR' && sleep 0.7 && ./build/relay_node --name Middle-1 --role middle --port 9002 --dir 127.0.0.1:8000" C-m

# 4. Exit Relay (Pane 3)
tmux split-window -t "$SESSION:0"
tmux select-layout -t "$SESSION:0" tiled
tmux send-keys -t "$SESSION:0.3" "cd '$DIR' && sleep 0.9 && ./build/relay_node --name Exit-1 --role exit --port 9003 --dir 127.0.0.1:8000" C-m

# 5. Destination Server (Pane 4)
tmux split-window -t "$SESSION:0"
tmux select-layout -t "$SESSION:0" tiled
tmux send-keys -t "$SESSION:0.4" "cd '$DIR' && sleep 1.1 && ./build/dest_server --port 9090" C-m

# 6. Onion Client CLI (Pane 5)
tmux split-window -t "$SESSION:0"
tmux select-layout -t "$SESSION:0" tiled
tmux send-keys -t "$SESSION:0.5" "cd '$DIR' && sleep 1.5 && ./build/onion_client --cli --web-port 8080 --dir 127.0.0.1:8000" C-m

# Final tiled arrangement & focus on Client CLI
tmux select-layout -t "$SESSION:0" tiled
tmux select-pane -t "$SESSION:0.5"

echo "[✓] All 6 panes initialized successfully!"
echo "Attaching to tmux now... (Focus is on Pane 5: Onion Client CLI)"
sleep 1
tmux attach-session -t "$SESSION"
