#!/usr/bin/env bash

echo "[*] Stopping all Mini-Tor nodes and services..."
pkill -f "build/dir_authority" 2>/dev/null || true
pkill -f "build/relay_node" 2>/dev/null || true
pkill -f "build/dest_server" 2>/dev/null || true
pkill -f "build/onion_client" 2>/dev/null || true

sleep 0.5
echo "[✓] All Mini-Tor processes stopped cleanly."
