#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <queue>
#include <sstream>
#include <csignal>
#include <unistd.h>

#include "../third_party/httplib.h"
#include "../third_party/json.hpp"
#include "../common/colors.hpp"
#include "../common/crypto.hpp"
#include "../common/protocol.hpp"
#include "../common/network.hpp"

using json = nlohmann::json;
using namespace minitor;

std::string current_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%H:%M:%S");
    return ss.str();
}

// Global Log Event Hub for Web UI SSE Stream
std::mutex g_logs_mutex;
std::vector<std::string> g_log_history;
std::vector<httplib::DataSink*> g_sse_clients;

void log_event(const std::string& level, const std::string& component, const std::string& message) {
    std::string ts = current_time();

    // 1. Terminal Colored Log
    std::string color_prefix = color::B_WHITE;
    if (level == "SUCCESS") color_prefix = color::B_GREEN;
    else if (level == "INFO") color_prefix = color::B_CYAN;
    else if (level == "WARN") color_prefix = color::B_YELLOW;
    else if (level == "ERROR") color_prefix = color::B_RED;
    else if (level == "CRYPTO") color_prefix = color::B_MAGENTA;
    else if (level == "PEEL") color_prefix = color::YELLOW;

    std::cout << color::DIM << "[" << ts << "] " << color::RESET
              << color_prefix << "[" << level << "] " << color::RESET
              << color::BOLD << "[" << component << "] " << color::RESET
              << message << std::endl;

    // 2. Broadcast to Web UI via SSE
    json log_item = {
        {"timestamp", ts},
        {"level", level},
        {"component", component},
        {"message", message}
    };
    std::string sse_data = "data: " + log_item.dump() + "\n\n";

    std::lock_guard<std::mutex> lock(g_logs_mutex);
    g_log_history.push_back(log_item.dump());
    if (g_log_history.size() > 100) g_log_history.erase(g_log_history.begin());

    for (auto it = g_sse_clients.begin(); it != g_sse_clients.end();) {
        if (*it && (*it)->is_writable()) {
            if (!(*it)->write(sse_data.data(), sse_data.size())) {
                it = g_sse_clients.erase(it);
            } else {
                ++it;
            }
        } else {
            it = g_sse_clients.erase(it);
        }
    }
}

class OnionClient {
public:
    uint32_t circuit_id{1001};
    int guard_fd{-1};

    protocol::RelayInfo guard_relay;
    protocol::RelayInfo middle_relay;
    protocol::RelayInfo exit_relay;

    std::vector<uint8_t> k1; // Guard session key (32 bytes AES-256)
    std::vector<uint8_t> k2; // Middle session key (32 bytes AES-256)
    std::vector<uint8_t> k3; // Exit session key (32 bytes AES-256)

    bool circuit_active{false};
    std::recursive_mutex client_mutex;

    ~OnionClient() {
        destroy_circuit();
    }

    void destroy_circuit() {
        std::lock_guard<std::recursive_mutex> lock(client_mutex);
        if (guard_fd >= 0) {
            close(guard_fd);
            guard_fd = -1;
        }
        circuit_active = false;
        k1.clear();
        k2.clear();
        k3.clear();
    }

    bool fetch_consensus(const std::string& dir_addr, std::vector<protocol::RelayInfo>& relays) {
        httplib::Client cli(dir_addr);
        cli.set_connection_timeout(2, 0);
        auto res = cli.Get("/consensus");
        if (!res || res->status != 200) {
            log_event("ERROR", "DIRECTORY", "Failed to retrieve consensus from " + dir_addr);
            return false;
        }

        try {
            auto body = json::parse(res->body);
            relays.clear();
            for (const auto& item : body["relays"]) {
                relays.push_back(protocol::RelayInfo::from_json(item));
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    bool build_circuit(const std::string& dir_addr, json& telemetry_out) {
        std::lock_guard<std::recursive_mutex> lock(client_mutex);
        destroy_circuit();

        log_event("INFO", "CIRCUIT", "Initiating 3-hop circuit construction...");

        std::vector<protocol::RelayInfo> relays;
        if (!fetch_consensus(dir_addr, relays)) {
            telemetry_out = {{"error", "Could not query directory authority"}};
            return false;
        }

        if (relays.size() < 3) {
            std::string err = "Need at least 3 active relays in network to build an onion circuit (found " + std::to_string(relays.size()) + ")";
            log_event("ERROR", "CIRCUIT", err);
            telemetry_out = {{"error", err}};
            return false;
        }

        // Pick Guard, Middle, Exit
        // Search by role first, or fallback to distinct relays
        protocol::RelayInfo* p_guard = nullptr;
        protocol::RelayInfo* p_middle = nullptr;
        protocol::RelayInfo* p_exit = nullptr;

        for (auto& r : relays) {
            if (r.role == "guard" && !p_guard) p_guard = &r;
            else if (r.role == "middle" && !p_middle) p_middle = &r;
            else if (r.role == "exit" && !p_exit) p_exit = &r;
        }

        // Fallback if roles not strictly separated
        for (auto& r : relays) {
            if (!p_guard) p_guard = &r;
            else if (!p_middle && &r != p_guard) p_middle = &r;
            else if (!p_exit && &r != p_guard && &r != p_middle) p_exit = &r;
        }

        if (!p_guard || !p_middle || !p_exit) {
            telemetry_out = {{"error", "Could not pick 3 distinct relays"}};
            return false;
        }

        guard_relay = *p_guard;
        middle_relay = *p_middle;
        exit_relay = *p_exit;

        log_event("INFO", "CIRCUIT", "Path selected: [Guard: " + guard_relay.name + "] -> [Middle: " + middle_relay.name + "] -> [Exit: " + exit_relay.name + "]");

        // ==========================================
        // HOP 1: Guard Node Handshake (CREATE / CREATED)
        // ==========================================
        log_event("INFO", "HOP 1", "Connecting to Guard node at " + guard_relay.ip + ":" + std::to_string(guard_relay.port));
        guard_fd = network::connect_to_server(guard_relay.ip, guard_relay.port);
        if (guard_fd < 0) {
            log_event("ERROR", "HOP 1", "Failed to connect to Guard node");
            telemetry_out = {{"error", "Guard connection failed"}};
            return false;
        }

        crypto::KeyPair ephem_1;
        protocol::Cell create_cell;
        create_cell.circuit_id = circuit_id;
        create_cell.command = protocol::CELL_CREATE;
        create_cell.payload = ephem_1.public_key;

        log_event("CRYPTO", "HOP 1", "Dispatched CELL_CREATE with client ephemeral pubkey (" + ephem_1.get_public_hex().substr(0, 16) + "...)");
        if (!network::send_cell(guard_fd, create_cell)) {
            log_event("ERROR", "HOP 1", "Failed to send CELL_CREATE");
            return false;
        }

        protocol::Cell created_cell_1;
        if (!network::recv_cell(guard_fd, created_cell_1) || created_cell_1.command != protocol::CELL_CREATED) {
            log_event("ERROR", "HOP 1", "Failed to receive valid CELL_CREATED from Guard");
            return false;
        }

        std::vector<uint8_t> secret_1;
        if (!crypto::derive_shared_secret(ephem_1, created_cell_1.payload, secret_1)) {
            log_event("ERROR", "HOP 1", "ECDH shared secret derivation failed with Guard");
            return false;
        }
        crypto::hkdf_sha256(secret_1, "mini-tor-session-key", 32, k1);

        log_event("SUCCESS", "HOP 1", "Established Hop 1 with Guard! Derived AES-256 Session Key: " + crypto::to_hex(k1.data(), 8) + "...");

        // ==========================================
        // HOP 2: Middle Node Telescopic Extension
        // ==========================================
        log_event("INFO", "HOP 2", "Telescoping circuit to Middle node (" + middle_relay.ip + ":" + std::to_string(middle_relay.port) + ")");
        crypto::KeyPair ephem_2;

        json extend_req_2 = {
            {"type", "EXTEND"},
            {"next_ip", middle_relay.ip},
            {"next_port", middle_relay.port},
            {"client_ephemeral_pubkey", ephem_2.get_public_hex()}
        };
        std::string ext_str_2 = extend_req_2.dump();
        std::vector<uint8_t> ext_bytes_2(ext_str_2.begin(), ext_str_2.end());
        std::vector<uint8_t> enc_ext_2;
        crypto::aes_gcm_encrypt(k1, ext_bytes_2, enc_ext_2);

        protocol::Cell extend_cell_2;
        extend_cell_2.circuit_id = circuit_id;
        extend_cell_2.command = protocol::CELL_RELAY_DATA;
        extend_cell_2.payload = enc_ext_2;

        if (!network::send_cell(guard_fd, extend_cell_2)) {
            log_event("ERROR", "HOP 2", "Failed to send extend request for Hop 2");
            return false;
        }

        protocol::Cell resp_ext_2;
        if (!network::recv_cell(guard_fd, resp_ext_2) || resp_ext_2.command != protocol::CELL_RELAY_DATA) {
            log_event("ERROR", "HOP 2", "Failed to receive extension response from Guard");
            return false;
        }

        std::vector<uint8_t> dec_ext_2;
        if (!crypto::aes_gcm_decrypt(k1, resp_ext_2.payload, dec_ext_2)) {
            log_event("ERROR", "HOP 2", "Failed to decrypt extension response from Guard");
            return false;
        }

        auto ext_resp_obj_2 = json::parse(std::string(dec_ext_2.begin(), dec_ext_2.end()));
        std::string middle_pubkey_hex = ext_resp_obj_2["pubkey"];
        std::vector<uint8_t> middle_pubkey = crypto::from_hex(middle_pubkey_hex);

        std::vector<uint8_t> secret_2;
        crypto::derive_shared_secret(ephem_2, middle_pubkey, secret_2);
        crypto::hkdf_sha256(secret_2, "mini-tor-session-key", 32, k2);

        log_event("SUCCESS", "HOP 2", "Established Hop 2 with Middle! Derived AES-256 Session Key: " + crypto::to_hex(k2.data(), 8) + "...");

        // ==========================================
        // HOP 3: Exit Node Telescopic Extension
        // ==========================================
        log_event("INFO", "HOP 3", "Telescoping circuit to Exit node (" + exit_relay.ip + ":" + std::to_string(exit_relay.port) + ")");
        crypto::KeyPair ephem_3;

        // Middle Layer command: EXTEND to Exit
        json extend_req_3 = {
            {"type", "EXTEND"},
            {"next_ip", exit_relay.ip},
            {"next_port", exit_relay.port},
            {"client_ephemeral_pubkey", ephem_3.get_public_hex()}
        };
        std::string ext_str_3 = extend_req_3.dump();
        std::vector<uint8_t> ext_bytes_3(ext_str_3.begin(), ext_str_3.end());
        std::vector<uint8_t> enc_ext_middle_3;
        crypto::aes_gcm_encrypt(k2, ext_bytes_3, enc_ext_middle_3);

        // Guard Layer command: FORWARD to Middle
        json fwd_guard_3 = {
            {"type", "FORWARD"},
            {"inner_data", crypto::to_hex(enc_ext_middle_3)}
        };
        std::string fwd_str_3 = fwd_guard_3.dump();
        std::vector<uint8_t> fwd_bytes_3(fwd_str_3.begin(), fwd_str_3.end());
        std::vector<uint8_t> enc_ext_guard_3;
        crypto::aes_gcm_encrypt(k1, fwd_bytes_3, enc_ext_guard_3);

        protocol::Cell extend_cell_3;
        extend_cell_3.circuit_id = circuit_id;
        extend_cell_3.command = protocol::CELL_RELAY_DATA;
        extend_cell_3.payload = enc_ext_guard_3;

        if (!network::send_cell(guard_fd, extend_cell_3)) {
            log_event("ERROR", "HOP 3", "Failed to send extend request for Hop 3");
            return false;
        }

        protocol::Cell resp_ext_3;
        if (!network::recv_cell(guard_fd, resp_ext_3) || resp_ext_3.command != protocol::CELL_RELAY_DATA) {
            log_event("ERROR", "HOP 3", "Failed to receive extension response for Hop 3");
            return false;
        }

        // Peel Guard layer K1
        std::vector<uint8_t> dec_ext_guard_3;
        if (!crypto::aes_gcm_decrypt(k1, resp_ext_3.payload, dec_ext_guard_3)) {
            log_event("ERROR", "HOP 3", "Failed to peel Guard layer on Hop 3 response");
            return false;
        }

        // Peel Middle layer K2
        std::vector<uint8_t> dec_ext_middle_3;
        if (!crypto::aes_gcm_decrypt(k2, dec_ext_guard_3, dec_ext_middle_3)) {
            log_event("ERROR", "HOP 3", "Failed to peel Middle layer on Hop 3 response");
            return false;
        }

        auto ext_resp_obj_3 = json::parse(std::string(dec_ext_middle_3.begin(), dec_ext_middle_3.end()));
        std::string exit_pubkey_hex = ext_resp_obj_3["pubkey"];
        std::vector<uint8_t> exit_pubkey = crypto::from_hex(exit_pubkey_hex);

        std::vector<uint8_t> secret_3;
        crypto::derive_shared_secret(ephem_3, exit_pubkey, secret_3);
        crypto::hkdf_sha256(secret_3, "mini-tor-session-key", 32, k3);

        log_event("SUCCESS", "HOP 3", "Established Hop 3 with Exit! Derived AES-256 Session Key: " + crypto::to_hex(k3.data(), 8) + "...");
        log_event("SUCCESS", "CIRCUIT", "3-Hop Onion Circuit #" + std::to_string(circuit_id) + " is fully established and READY!");

        circuit_active = true;

        telemetry_out = {
            {"status", "active"},
            {"circuit_id", circuit_id},
            {"hops", {
                {
                    {"role", "guard"},
                    {"name", guard_relay.name},
                    {"ip", guard_relay.ip},
                    {"port", guard_relay.port},
                    {"session_key", crypto::to_hex(k1.data(), 8) + "..."}
                },
                {
                    {"role", "middle"},
                    {"name", middle_relay.name},
                    {"ip", middle_relay.ip},
                    {"port", middle_relay.port},
                    {"session_key", crypto::to_hex(k2.data(), 8) + "..."}
                },
                {
                    {"role", "exit"},
                    {"name", exit_relay.name},
                    {"ip", exit_relay.ip},
                    {"port", exit_relay.port},
                    {"session_key", crypto::to_hex(k3.data(), 8) + "..."}
                }
            }}
        };
        return true;
    }

    bool send_message(const std::string& dest_ip, int dest_port, const std::string& message, json& telemetry_out) {
        std::lock_guard<std::recursive_mutex> lock(client_mutex);
        if (!circuit_active || guard_fd < 0) {
            telemetry_out = {{"error", "No active circuit. Build a circuit first."}};
            return false;
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        log_event("INFO", "ONION", "Encrypting payload in 3 concentric layers for destination: " + dest_ip + ":" + std::to_string(dest_port));

        // ----------------------------------------------------
        // LAYER 3 (Exit Node): Contains Plaintext & Destination
        // ----------------------------------------------------
        json p3 = {
            {"type", "DEST"},
            {"dest_ip", dest_ip},
            {"dest_port", dest_port},
            {"body", message}
        };
        std::string p3_str = p3.dump();
        std::vector<uint8_t> p3_bytes(p3_str.begin(), p3_str.end());
        std::vector<uint8_t> c3;
        crypto::aes_gcm_encrypt(k3, p3_bytes, c3);

        log_event("CRYPTO", "LAYER 3 (EXIT)", "Wrapped message with Exit Key K3 (" + std::to_string(c3.size()) + " bytes ciphertext)");

        // ----------------------------------------------------
        // LAYER 2 (Middle Node): FORWARD wrapper
        // ----------------------------------------------------
        json p2 = {
            {"type", "FORWARD"},
            {"inner_data", crypto::to_hex(c3)}
        };
        std::string p2_str = p2.dump();
        std::vector<uint8_t> p2_bytes(p2_str.begin(), p2_str.end());
        std::vector<uint8_t> c2;
        crypto::aes_gcm_encrypt(k2, p2_bytes, c2);

        log_event("CRYPTO", "LAYER 2 (MIDDLE)", "Wrapped Layer 3 with Middle Key K2 (" + std::to_string(c2.size()) + " bytes ciphertext)");

        // ----------------------------------------------------
        // LAYER 1 (Guard Node): FORWARD wrapper
        // ----------------------------------------------------
        json p1 = {
            {"type", "FORWARD"},
            {"inner_data", crypto::to_hex(c2)}
        };
        std::string p1_str = p1.dump();
        std::vector<uint8_t> p1_bytes(p1_str.begin(), p1_str.end());
        std::vector<uint8_t> c1;
        crypto::aes_gcm_encrypt(k1, p1_bytes, c1);

        log_event("CRYPTO", "LAYER 1 (GUARD)", "Wrapped Layer 2 with Guard Key K1 (" + std::to_string(c1.size()) + " bytes ciphertext)");

        // Dispatch onion packet
        protocol::Cell data_cell;
        data_cell.circuit_id = circuit_id;
        data_cell.command = protocol::CELL_RELAY_DATA;
        data_cell.payload = c1;

        log_event("INFO", "NETWORK", "Dispatching fully encrypted 3-layer Onion Cell to Guard node...");
        if (!network::send_cell(guard_fd, data_cell)) {
            log_event("ERROR", "NETWORK", "Failed to send data cell to Guard");
            return false;
        }

        // Wait for response
        protocol::Cell resp_cell;
        if (!network::recv_cell(guard_fd, resp_cell) || resp_cell.command != protocol::CELL_RELAY_DATA) {
            log_event("ERROR", "NETWORK", "Failed to receive response cell from circuit");
            return false;
        }

        log_event("PEEL", "RETURN PATH", "Received response from Guard (" + std::to_string(resp_cell.payload.size()) + " bytes). Peeling layers in reverse...");

        // Reverse peeling:
        // 1. Peel Guard layer
        std::vector<uint8_t> r1;
        if (!crypto::aes_gcm_decrypt(k1, resp_cell.payload, r1)) {
            log_event("ERROR", "PEEL", "Failed to peel Guard layer on response");
            return false;
        }
        log_event("PEEL", "HOP 1", "Peeled Guard response layer (K1)");

        // 2. Peel Middle layer
        std::vector<uint8_t> r2;
        if (!crypto::aes_gcm_decrypt(k2, r1, r2)) {
            log_event("ERROR", "PEEL", "Failed to peel Middle response layer");
            return false;
        }
        log_event("PEEL", "HOP 2", "Peeled Middle response layer (K2)");

        // 3. Peel Exit layer
        std::vector<uint8_t> r3;
        if (!crypto::aes_gcm_decrypt(k3, r2, r3)) {
            log_event("ERROR", "PEEL", "Failed to peel Exit response layer");
            return false;
        }
        log_event("PEEL", "HOP 3", "Peeled Exit response layer (K3) -> Plaintext recovered!");

        std::string final_plaintext(r3.begin(), r3.end());
        auto end_time = std::chrono::high_resolution_clock::now();
        double latency_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

        log_event("SUCCESS", "DESTINATION", "Verified plaintext response received (" + std::to_string(final_plaintext.size()) + " bytes) in " + std::to_string((int)latency_ms) + " ms");

        telemetry_out = {
            {"status", "success"},
            {"latency_ms", latency_ms},
            {"layers", {
                {
                    {"hop", 1},
                    {"node", guard_relay.name},
                    {"role", "guard"},
                    {"ciphertext_hex_preview", crypto::to_hex(c1.data(), std::min((size_t)32, c1.size())) + "..."},
                    {"total_bytes", c1.size()}
                },
                {
                    {"hop", 2},
                    {"node", middle_relay.name},
                    {"role", "middle"},
                    {"ciphertext_hex_preview", crypto::to_hex(c2.data(), std::min((size_t)32, c2.size())) + "..."},
                    {"total_bytes", c2.size()}
                },
                {
                    {"hop", 3},
                    {"node", exit_relay.name},
                    {"role", "exit"},
                    {"ciphertext_hex_preview", crypto::to_hex(c3.data(), std::min((size_t)32, c3.size())) + "..."},
                    {"total_bytes", c3.size()}
                }
            }},
            {"original_message", message},
            {"destination", dest_ip + ":" + std::to_string(dest_port)},
            {"response_plaintext", final_plaintext}
        };

        return true;
    }
};

OnionClient g_client;
std::string g_dir_addr = "127.0.0.1:8000";

void run_web_gateway(int web_port) {
    httplib::Server svr;

    // Enable CORS
    auto set_cors = [](httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
    };

    svr.Options(".*", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        res.status = 200;
    });

    // 1. Directory Consensus
    svr.Get("/api/consensus", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        std::vector<protocol::RelayInfo> relays;
        if (g_client.fetch_consensus(g_dir_addr, relays)) {
            json arr = json::array();
            for (const auto& r : relays) arr.push_back(r.to_json());
            json resp = {{"relays", arr}};
            res.set_content(resp.dump(), "application/json");
        } else {
            res.status = 502;
            res.set_content("{\"error\":\"Directory Authority unreachable\"}", "application/json");
        }
    });

    // 2. Current Circuit Status
    svr.Get("/api/circuit", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        json resp;
        if (g_client.circuit_active) {
            resp = {
                {"active", true},
                {"circuit_id", g_client.circuit_id},
                {"hops", {
                    {{"role", "guard"}, {"name", g_client.guard_relay.name}, {"ip", g_client.guard_relay.ip}, {"port", g_client.guard_relay.port}, {"session_key", crypto::to_hex(g_client.k1.data(), 8) + "..."}},
                    {{"role", "middle"}, {"name", g_client.middle_relay.name}, {"ip", g_client.middle_relay.ip}, {"port", g_client.middle_relay.port}, {"session_key", crypto::to_hex(g_client.k2.data(), 8) + "..."}},
                    {{"role", "exit"}, {"name", g_client.exit_relay.name}, {"ip", g_client.exit_relay.ip}, {"port", g_client.exit_relay.port}, {"session_key", crypto::to_hex(g_client.k3.data(), 8) + "..."}}
                }}
            };
        } else {
            resp = {{"active", false}};
        }
        res.set_content(resp.dump(), "application/json");
    });

    // 3. Build Circuit
    svr.Post("/api/circuit/build", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        json telemetry;
        bool ok = g_client.build_circuit(g_dir_addr, telemetry);
        if (ok) {
            res.set_content(telemetry.dump(), "application/json");
        } else {
            res.status = 400;
            res.set_content(telemetry.dump(), "application/json");
        }
    });

    // 4. Send Message via Circuit
    svr.Post("/api/send", [&](const httplib::Request& req, httplib::Response& res) {
        set_cors(res);
        try {
            auto body = json::parse(req.body);
            std::string dest_ip = body.value("dest_ip", "127.0.0.1");
            int dest_port = body.value("dest_port", 9090);
            std::string msg = body.value("message", "Hello Onion Routing!");

            json telemetry;
            bool ok = g_client.send_message(dest_ip, dest_port, msg, telemetry);
            if (ok) {
                res.set_content(telemetry.dump(), "application/json");
            } else {
                res.status = 400;
                res.set_content(telemetry.dump(), "application/json");
            }
        } catch (const std::exception& e) {
            res.status = 400;
            json err = {{"error", e.what()}};
            res.set_content(err.dump(), "application/json");
        }
    });

    // 5. Server-Sent Events (SSE) log stream
    svr.Get("/api/events", [&](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");

        res.set_chunked_content_provider("text/event-stream",
            [](size_t, httplib::DataSink& sink) {
                {
                    std::lock_guard<std::mutex> lock(g_logs_mutex);
                    g_sse_clients.push_back(&sink);

                    // Send past logs
                    for (const auto& log_str : g_log_history) {
                        std::string sse_item = "data: " + log_str + "\n\n";
                        sink.write(sse_item.data(), sse_item.size());
                    }
                }

                // Keep connection open
                while (sink.is_writable()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(250));
                }

                {
                    std::lock_guard<std::mutex> lock(g_logs_mutex);
                    auto it = std::find(g_sse_clients.begin(), g_sse_clients.end(), &sink);
                    if (it != g_sse_clients.end()) {
                        g_sse_clients.erase(it);
                    }
                }
                return true;
            },
            [](bool) {
                // Connection closed
            }
        );
    });

    // 6. Serve static Web Dashboard files
    svr.set_mount_point("/", "./web");

    std::cout << color::B_GREEN << "[WEB GATEWAY] Embedded Web Dashboard live at: "
              << color::BOLD << color::B_WHITE << "http://127.0.0.1:" << web_port << color::RESET << std::endl;

    svr.listen("0.0.0.0", web_port);
}

void run_terminal_cli() {
    std::cout << color::B_CYAN << color::BOLD;
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        MINI-TOR: COMPUTER NETWORKS PROTOCOL TERMINAL         ║\n";
    std::cout << "║        Layer 4/7 Onion Routing & Applied Cryptography        ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << color::RESET << std::endl;

    while (true) {
        std::cout << "\n" << color::BOLD << "============ MINI-TOR CN PROTOCOL MENU ============" << color::RESET << "\n";
        std::cout << "1. " << color::WHITE << "Query Directory Consensus (Registered Relays)" << color::RESET << "\n";
        std::cout << "2. " << color::B_GREEN << "Telescoping Circuit Handshake (X25519 ECDH + HKDF)" << color::RESET << "\n";
        std::cout << "3. " << color::B_YELLOW << "Send 3-Layer Encrypted Onion Packet (Live Peeling)" << color::RESET << "\n";
        std::cout << "4. " << color::B_MAGENTA << "Inspect Active Circuit Sockets & Session Keys" << color::RESET << "\n";
        std::cout << "5. " << color::B_CYAN << "View Wire Protocol Cell Framing Spec" << color::RESET << "\n";
        std::cout << "6. " << color::RED << "Destroy Active Circuit (Send CELL_DESTROY)" << color::RESET << "\n";
        std::cout << "7. " << color::DIM << "Exit Terminal CLI" << color::RESET << "\n";
        std::cout << color::CYAN << "Select Option [1-7]: " << color::RESET;

        std::string input_line;
        if (!std::getline(std::cin, input_line)) {
            break;
        }

        // Strip whitespace and escape chars
        while (!input_line.empty() && (input_line.front() == ' ' || input_line.front() == '\t' || input_line.front() == '\r')) input_line.erase(input_line.begin());
        while (!input_line.empty() && (input_line.back() == ' ' || input_line.back() == '\t' || input_line.back() == '\r')) input_line.pop_back();

        if (input_line.empty()) continue;

        int choice = 0;
        try {
            choice = std::stoi(input_line);
        } catch (...) {
            continue;
        }

        if (choice == 1) {
            std::vector<protocol::RelayInfo> relays;
            if (g_client.fetch_consensus(g_dir_addr, relays)) {
                std::cout << "\n" << color::B_GREEN << "=== DIRECTORY CONSENSUS DOCUMENT (" << relays.size() << " Active Relays) ===" << color::RESET << "\n";
                std::cout << std::left << std::setw(12) << "RELAY NAME"
                          << std::setw(10) << "ROLE"
                          << std::setw(20) << "SOCKET ADDRESS"
                          << "IDENTITY PUBLIC KEY (X25519)\n";
                std::cout << std::string(75, '-') << "\n";
                for (const auto& r : relays) {
                    std::string role_c = (r.role == "guard") ? color::B_GREEN : (r.role == "middle" ? color::B_CYAN : color::B_MAGENTA);
                    std::cout << std::left << std::setw(12) << r.name
                              << role_c << std::setw(10) << r.role << color::RESET
                              << std::setw(20) << (r.ip + ":" + std::to_string(r.port))
                              << color::DIM << r.identity_pubkey_hex << color::RESET << "\n";
                }
            } else {
                std::cout << color::RED << "Failed to fetch consensus from " << g_dir_addr << color::RESET << "\n";
            }
        } else if (choice == 2) {
            json telemetry;
            bool ok = g_client.build_circuit(g_dir_addr, telemetry);
            if (ok) {
                std::cout << "\n" << color::B_GREEN << ">>> 3-HOP CIRCUIT #" << g_client.circuit_id << " READY! <<<" << color::RESET << "\n";
                std::cout << "• Hop 1 (Guard):  " << g_client.guard_relay.name << " (" << g_client.guard_relay.ip << ":" << g_client.guard_relay.port << ")\n";
                std::cout << "• Hop 2 (Middle): " << g_client.middle_relay.name << " (" << g_client.middle_relay.ip << ":" << g_client.middle_relay.port << ")\n";
                std::cout << "• Hop 3 (Exit):   " << g_client.exit_relay.name << " (" << g_client.exit_relay.ip << ":" << g_client.exit_relay.port << ")\n";
            }
        } else if (choice == 3) {
            if (!g_client.circuit_active) {
                std::cout << color::YELLOW << "[!] No circuit active yet. Automatically establishing 3-hop circuit first..." << color::RESET << "\n";
                json c_telemetry;
                if (!g_client.build_circuit(g_dir_addr, c_telemetry)) {
                    std::cout << color::RED << "[!] Failed to build circuit. Is Directory Authority running?" << color::RESET << "\n";
                    continue;
                }
                std::cout << color::B_GREEN << "[✓] 3-Hop Circuit #" << g_client.circuit_id << " established automatically!" << color::RESET << "\n\n";
            }

            std::cout << color::CYAN << "Enter Target Server IP (press Enter for default 127.0.0.1): " << color::RESET;
            std::string dest_ip;
            std::getline(std::cin, dest_ip);
            if (dest_ip.empty()) dest_ip = "127.0.0.1";

            std::cout << color::CYAN << "Enter Target Server Port (press Enter for default 9090): " << color::RESET;
            std::string port_str;
            std::getline(std::cin, port_str);
            int dest_port = 9090;
            if (!port_str.empty()) {
                try {
                    dest_port = std::stoi(port_str);
                } catch (...) {
                    std::cout << color::YELLOW << "Non-numeric port entered. Defaulting to 9090." << color::RESET << "\n";
                    dest_port = 9090;
                }
            }

            std::cout << color::CYAN << "Enter Message to Send Secretly (or press Enter for sample): " << color::RESET;
            std::string msg;
            std::getline(std::cin, msg);
            if (msg.empty()) msg = "CONFIDENTIAL ONION PACKET #42";

            json telemetry;
            bool ok = g_client.send_message(dest_ip, dest_port, msg, telemetry);
            if (ok) {
                std::cout << "\n" << color::B_GREEN << "=== ONION PACKET TRANSMISSION SUMMARY ===" << color::RESET << "\n";
                std::cout << "Destination:          " << dest_ip << ":" << dest_port << "\n";
                std::cout << "Round-Trip Latency:   " << color::BOLD << telemetry["latency_ms"] << " ms" << color::RESET << "\n";
                std::cout << "\n--- Concentric Onion Layers Peeled ---\n";
                for (const auto& layer : telemetry["layers"]) {
                    std::cout << "• Hop " << layer["hop"] << " [" << layer["role"] << " - " << layer["node"] << "]: "
                              << "Size: " << layer["total_bytes"] << " bytes | Ciphertext: "
                              << color::CYAN << layer["ciphertext_hex_preview"] << color::RESET << "\n";
                }
                std::cout << "\n--- Plaintext Response from Destination ---\n";
                std::cout << color::B_WHITE << telemetry["response_plaintext"] << color::RESET << "\n";
            }
        } else if (choice == 4) {
            if (!g_client.circuit_active) {
                std::cout << color::YELLOW << "No active circuit. Build a circuit first (Option 2)." << color::RESET << "\n";
            } else {
                std::cout << "\n" << color::B_CYAN << "=== ACTIVE CIRCUIT CRYPTOGRAPHIC KEYS & SOCKETS ===" << color::RESET << "\n";
                std::cout << "Circuit ID:          #" << g_client.circuit_id << "\n";
                std::cout << "Client Socket FD:    " << g_client.guard_fd << " (TCP connection to Guard)\n";
                std::cout << "K1 (Guard AES-256):  " << crypto::to_hex(g_client.k1.data(), 32) << "\n";
                std::cout << "K2 (Middle AES-256): " << crypto::to_hex(g_client.k2.data(), 32) << "\n";
                std::cout << "K3 (Exit AES-256):   " << crypto::to_hex(g_client.k3.data(), 32) << "\n";
                std::cout << "Key Derivation:      X25519 Ephemeral ECDH + HKDF-SHA256\n";
                std::cout << "AEAD Cipher:         AES-256-GCM (12-byte Nonce + 16-byte Poly1305/GCM Tag)\n";
            }
        } else if (choice == 5) {
            std::cout << "\n" << color::B_MAGENTA << "=== MINI-TOR WIRE PROTOCOL CELL FRAMING ===" << color::RESET << "\n";
            std::cout << "Every packet traveling over TCP sockets conforms to this 9-byte binary header:\n";
            std::cout << "┌───────────────────┬────────────────┬───────────────────┬──────────────────────┐\n";
            std::cout << "│ Circuit ID (4 B)  │ Command (1 B)  │ Payload Len (4 B) │ Payload (N Bytes)    │\n";
            std::cout << "│ (Network Order)   │ 0x01..0x06     │ (Network Order)   │ (AES-256 Ciphertext) │\n";
            std::cout << "└───────────────────┴────────────────┴───────────────────┴──────────────────────┘\n";
            std::cout << "Commands:\n";
            std::cout << "  0x01 = CELL_CREATE         (Initiates Diffie-Hellman handshake)\n";
            std::cout << "  0x02 = CELL_CREATED        (Relay response with ephemeral pubkey)\n";
            std::cout << "  0x03 = CELL_RELAY_EXTEND   (Requests existing hop to extend circuit)\n";
            std::cout << "  0x04 = CELL_RELAY_EXTENDED (Hop returns next relay's pubkey)\n";
            std::cout << "  0x05 = CELL_RELAY_DATA     (Multi-layer encrypted payload or response)\n";
            std::cout << "  0x06 = CELL_DESTROY        (Tears down circuit and closes sockets)\n";
        } else if (choice == 6) {
            g_client.destroy_circuit();
            std::cout << color::GREEN << "Circuit destroyed and socket closed." << color::RESET << "\n";
        } else if (choice == 7) {
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    int web_port = 8080;
    bool cli_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--web-port" && i + 1 < argc) web_port = std::stoi(argv[++i]);
        else if (arg == "--dir" && i + 1 < argc) g_dir_addr = argv[++i];
        else if (arg == "--cli") cli_mode = true;
    }

    std::cout << color::B_CYAN << color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        MINI-TOR ONION CLIENT & WEB GATEWAY                   ║\n";
    std::cout << "║        Directory Authority: " << std::left << std::setw(32) << g_dir_addr << "║\n";
    std::cout << "║        Web Dashboard Port:  " << std::left << std::setw(32) << web_port << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << color::RESET << std::endl;

    if (cli_mode) {
        // Run Web Server in background thread so Web UI is also accessible!
        std::thread([web_port]() {
            run_web_gateway(web_port);
        }).detach();

        // Run interactive CLI in foreground
        run_terminal_cli();
    } else {
        // Run Web Gateway in foreground
        run_web_gateway(web_port);
    }

    return 0;
}
