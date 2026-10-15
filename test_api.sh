#!/usr/bin/env bash
set -e

# Start Directory Authority
./build/dir_authority --port 8000 &
PID_D=$!

# Start Destination Server
./build/dest_server --port 9090 &
PID_DEST=$!

sleep 0.5

# Start Relays
./build/relay_node --name Guard-1 --role guard --port 9001 --dir 127.0.0.1:8000 &
PID_G=$!
./build/relay_node --name Middle-1 --role middle --port 9002 --dir 127.0.0.1:8000 &
PID_M=$!
./build/relay_node --name Exit-1 --role exit --port 9003 --dir 127.0.0.1:8000 &
PID_E=$!

sleep 1

# Start Onion Client / Gateway
./build/onion_client --web-port 8080 --dir 127.0.0.1:8000 &
PID_CLI=$!

sleep 1

echo "=========================================="
echo "--- 1. Testing Consensus API ---"
echo "=========================================="
curl -s http://127.0.0.1:8080/api/consensus

echo ""
echo "=========================================="
echo "--- 2. Building 3-Hop Circuit via API ---"
echo "=========================================="
curl -s -X POST http://127.0.0.1:8080/api/circuit/build

echo ""
echo "=========================================="
echo "--- 3. Transmitting Onion Message ---"
echo "=========================================="
curl -s -X POST http://127.0.0.1:8080/api/send -H "Content-Type: application/json" \
  -d '{"dest_ip":"127.0.0.1","dest_port":9090,"message":"Hello College Project Evaluators!"}'

echo ""
echo "=========================================="
echo "--- TEST COMPLETE ---"
echo "=========================================="

kill $PID_CLI $PID_E $PID_M $PID_G $PID_DEST $PID_D 2>/dev/null || true
