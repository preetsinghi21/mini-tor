# Mini-Tor: Onion Routing Protocol Implementation (C++)

A production-grade, localized implementation of the **Tor (The Onion Router) Protocol** built in modern C++17 with OpenSSL 3 cryptography, interactive terminal displays, and a real-time web dashboard controller.

---

## 🌟 Key Features

1. **Applied Cryptography Stack**:
   - **Key Exchange (ECDH)**: Curve25519 (`X25519`) ephemeral Diffie-Hellman handshakes.
   - **Key Derivation (KDF)**: `HKDF-SHA256` deriving 256-bit symmetric session keys and nonces.
   - **Authenticated Encryption (AEAD)**: 3 concentric layers of `AES-256-GCM` with 16-byte authentication tags.
2. **True Telescopic Circuit Construction**:
   - Circuits are extended **hop-by-hop** (`Guard` $\to$ `Middle` $\to$ `Exit`), matching the authentic Tor specification.
   - No single relay knows both the client origin and the final destination.
3. **Dual Execution Interfaces**:
   - **Terminal Mode**: Colored ANSI logs across each node showing cell framing, ECDH derivation, and onion layer peeling.
   - **Live Web Application (Port 8080)**: Interactive cyberpunk dashboard that **actually controls and drives the C++ network** (live circuit construction, live onion packet transmission, real-time layer peeling animations, and SSE log streaming).
4. **Anonymity & Eavesdropper Verification**:
   - Target server logs demonstrate that it only sees the Exit node's IP address.
   - Interactive security analyzer breaks down what an attacker on any link can see.

---

## 🏗️ System Architecture

```
                               ┌────────────────────────────────┐
                               │   Directory Authority (C++)    │
                               │  Port 8000: Tracks all relays  │
                               └──────────────▲─────────────────┘
                                              │ Query Consensus / Register
                 ┌────────────────────────────┼────────────────────────────┐
                 │                            │                            │
   ┌─────────────┴─────────────┐┌─────────────┴─────────────┐┌─────────────┴─────────────┐
   │     Guard Relay (C++)     ││    Middle Relay (C++)     ││     Exit Relay (C++)      │
   │         Port 9001         ││         Port 9002         ││         Port 9003         │
   └─────────────▲─────────────┘└─────────────▲─────────────┘└─────────────┬─────────────┘
                 │ (Hop 1: C1)                │ (Hop 2: C2)                │ (Plaintext)
                 │ Decrypts Layer 1           │ Decrypts Layer 2           │ Decrypts Layer 3
                 │                            │                            ▼
   ┌─────────────┴────────────────────────────┴─────────────┐┌───────────────────────────┐
   │                Onion Client Core (C++)                 ││ Destination Server (C++)  │
   │  - Telescoping Handshakes (X25519 + HKDF)              ││ Port 9090 (Target Server) │
   │  - 3-Layer AES-256-GCM Encryption / Decryption         ││ "I only see Exit's IP!"   │
   │  - Terminal Interactive CLI & Live Web Gateway (8080)  │└───────────────────────────┘
   └────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### 1. Build the Codebase
Make sure `g++` (C++17), `make`, and `libcrypto` (OpenSSL) are installed:
```bash
make -j4
```
This compiles four standalone binaries into `build/`:
- `build/dir_authority`
- `build/relay_node`
- `build/dest_server`
- `build/onion_client`

---

### 2. Launching the Network

#### Option A: One-Click Background Runner + Web Dashboard (Recommended for Presentation)
```bash
./scripts/run_all.sh
```
Open your browser and navigate to:
👉 **[http://127.0.0.1:8080](http://127.0.0.1:8080)**

Inside the Web Dashboard:
1. Click **"Establish 3-Hop Circuit"** $\to$ triggers real C++ Diffie-Hellman handshakes across Guard, Middle, and Exit.
2. Type any message and click **"Transmit Across C++ Onion Circuit"** $\to$ watch the 3 layers peel in real-time and observe the verified destination response!
3. Watch the **Live C++ Log Stream** in the right column mirroring all terminal outputs in real-time.

To stop the network:
```bash
./scripts/stop_all.sh
```

---

#### Option B: 6-Pane Terminal Dashboard (Using `tmux`)
For a terminal presentation:
```bash
./scripts/run_tmux.sh
```
This splits your terminal into 6 live panes:
- **Pane 0**: Directory Authority
- **Pane 1**: Guard Relay
- **Pane 2**: Middle Relay
- **Pane 3**: Exit Relay
- **Pane 4**: Destination Target Server
- **Pane 5**: Interactive Onion Client CLI

*(To detach from tmux, press `Ctrl+b` then `d`. To exit all panes, run `./scripts/stop_all.sh`)*

---

#### Option C: Manual Terminal Execution (Step-by-Step)
You can open 6 separate terminal tabs/windows:

1. **Terminal 1: Directory Authority**
   ```bash
   ./build/dir_authority --port 8000
   ```
2. **Terminal 2: Destination Server**
   ```bash
   ./build/dest_server --port 9090
   ```
3. **Terminal 3: Guard Relay**
   ```bash
   ./build/relay_node --name Guard-1 --role guard --port 9001 --dir 127.0.0.1:8000
   ```
4. **Terminal 4: Middle Relay**
   ```bash
   ./build/relay_node --name Middle-1 --role middle --port 9002 --dir 127.0.0.1:8000
   ```
5. **Terminal 5: Exit Relay**
   ```bash
   ./build/relay_node --name Exit-1 --role exit --port 9003 --dir 127.0.0.1:8000
   ```
6. **Terminal 6: Client CLI**
   ```bash
   ./build/onion_client --cli --web-port 8080 --dir 127.0.0.1:8000
   ```

---

## 🔒 Cryptographic Lifecycle

### 1. Telescopic Circuit Handshake
- **Hop 1 (Guard)**: Client sends `CELL_CREATE` with client ephemeral pubkey $A_1$. Guard replies with ephemeral pubkey $B_1$. Both compute $S_1 = \text{ECDH}(A_1, B_1)$, and derive $K_1 = \text{HKDF}(S_1)$.
- **Hop 2 (Middle)**: Client encrypts $A_2$ under $K_1$ in an `EXTEND` cell. Guard connects to Middle, sends `CELL_CREATE`, gets $B_2$, and relays it back encrypted under $K_1$. Client and Middle compute $S_2 = \text{ECDH}(A_2, B_2)$, deriving $K_2 = \text{HKDF}(S_2)$.
- **Hop 3 (Exit)**: Client encrypts $A_3$ under $K_2$, and wraps it under $K_1$. Guard forwards to Middle; Middle connects to Exit, gets $B_3$, and relays it back through Middle ($K_2$) and Guard ($K_1$). Client derives $K_3 = \text{HKDF}(S_3)$.

### 2. Multi-Layer Onion Encryption
When transmitting a payload to `destination:9090`:
$$C_3 = \text{AES-256-GCM}_{K_3}\Big(\{\text{"type": "DEST", "dest": "127.0.0.1:9090", "body": "Hello"}\}\Big)$$
$$C_2 = \text{AES-256-GCM}_{K_2}\Big(\{\text{"type": "FORWARD", "inner": } C_3\}\Big)$$
$$C_1 = \text{AES-256-GCM}_{K_1}\Big(\{\text{"type": "FORWARD", "inner": } C_2\}\Big)$$

The client sends $C_1$ to the Guard relay.
- Guard decrypts with $K_1 \implies$ strips layer 1, forwards $C_2$ to Middle.
- Middle decrypts with $K_2 \implies$ strips layer 2, forwards $C_3$ to Exit.
- Exit decrypts with $K_3 \implies$ strips layer 3, sees `"DEST": 127.0.0.1:9090`, connects to the destination, and forwards `"Hello"`.
- Return response is encrypted symmetrically in reverse ($K_3 \to K_2 \to K_1$) back to the client!

---

## 🎓 College Presentation & Evaluation Checklist

1. **Demonstrate Layer Peeling in the Web UI**:
   - Send a message from the Web UI.
   - Point out the 3 layer cards: show the evaluators that each layer displays real 256-bit ciphertext bytes that shrink as each relay strips a shell.
2. **Demonstrate Anonymity on the Destination Server**:
   - Show the `dest_server` terminal logs:
     `[NEW CONNECTION] Inbound TCP connection from 127.0.0.1:52422 (Exit Relay Node)`
     `[PRIVACY CHECK] Destination server has ZERO knowledge of the original client's IP!`
3. **Explain the Eavesdropper Threat Model**:
   - Use the built-in "Wireshark Security Analysis" tab to show that an ISP monitoring the Client only sees encrypted traffic to the Guard node, with zero knowledge of the destination or message.
