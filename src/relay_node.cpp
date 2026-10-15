#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../third_party/httplib.h"
#include "../third_party/json.hpp"
#include "../common/colors.hpp"
#include "../common/crypto.hpp"
#include "../common/protocol.hpp"
#include "../common/network.hpp"

using json = nlohmann::json;
using namespace minitor;

struct CircuitContext {
    uint32_t circuit_id{0};
    std::vector<uint8_t> session_key; // 32-byte AES key
    int prev_fd{-1};                   // Upstream connection (Client or previous relay)
    int next_fd{-1};                   // Downstream connection (Next relay)
};

std::string g_name = "Relay-1";
std::string g_role = "relay"; // "guard", "middle", "exit"
int g_port = 9001;
std::string g_dir_addr = "127.0.0.1:8000";
int g_server_fd = -1;

std::mutex g_circuits_mutex;
std::map<uint32_t, CircuitContext> g_circuits;

void sig_handler(int) {
    std::cout << "\n" << color::YELLOW << "[" << g_name << "] Shutting down relay..." << color::RESET << std::endl;
    if (g_server_fd >= 0) close(g_server_fd);
    exit(0);
}

std::string current_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%H:%M:%S");
    return ss.str();
}

std::string role_color(const std::string& role) {
    if (role == "guard") return color::B_GREEN;
    if (role == "middle") return color::B_CYAN;
    if (role == "exit") return color::B_MAGENTA;
    return color::YELLOW;
}

// Background thread to relay return packets from next_fd back to prev_fd
void relay_backward_worker(uint32_t cid, int next_fd, int prev_fd, std::vector<uint8_t> session_key) {
    while (true) {
        protocol::Cell back_cell;
        if (!network::recv_cell(next_fd, back_cell)) {
            break;
        }

        // Encrypt with our session key on the return path
        std::vector<uint8_t> re_encrypted;
        if (!crypto::aes_gcm_encrypt(session_key, back_cell.payload, re_encrypted)) {
            std::cerr << color::RED << "[" << g_name << "] Failed to encrypt backward response" << color::RESET << std::endl;
            break;
        }

        back_cell.payload = re_encrypted;
        if (!network::send_cell(prev_fd, back_cell)) {
            break;
        }

        std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                  << color::B_BLUE << "[RETURN RELAY] " << color::RESET
                  << "Circuit " << cid << ": Wrapped response with our session key ("
                  << re_encrypted.size() << " bytes), sent upstream." << std::endl;
    }
}

void handle_upstream_connection(int client_fd) {
    while (true) {
        protocol::Cell cell;
        if (!network::recv_cell(client_fd, cell)) {
            break;
        }

        uint32_t cid = cell.circuit_id;

        // 1. CELL_CREATE: Handshake with client or prev hop
        if (cell.command == protocol::CELL_CREATE) {
            std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                      << color::B_YELLOW << "[CELL_CREATE] " << color::RESET
                      << "Received handshake initiation for Circuit #" << color::BOLD << cid << color::RESET
                      << " (Client PubKey: " << crypto::to_hex(cell.payload.data(), std::min((size_t)8, cell.payload.size())) << "...)"
                      << std::endl;

            // Generate ephemeral key pair
            crypto::KeyPair ephemeral_key;

            // Derive shared secret
            std::vector<uint8_t> shared_secret;
            if (!crypto::derive_shared_secret(ephemeral_key, cell.payload, shared_secret)) {
                std::cerr << color::RED << "[" << g_name << "] Diffie-Hellman derivation failed!" << color::RESET << std::endl;
                break;
            }

            // Derive AES-256 session key
            std::vector<uint8_t> session_key;
            if (!crypto::hkdf_sha256(shared_secret, "mini-tor-session-key", 32, session_key)) {
                std::cerr << color::RED << "[" << g_name << "] HKDF key derivation failed!" << color::RESET << std::endl;
                break;
            }

            {
                std::lock_guard<std::mutex> lock(g_circuits_mutex);
                CircuitContext ctx;
                ctx.circuit_id = cid;
                ctx.session_key = session_key;
                ctx.prev_fd = client_fd;
                ctx.next_fd = -1;
                g_circuits[cid] = ctx;
            }

            std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                      << color::B_GREEN << "[ECDH HANDSHAKE OK] " << color::RESET
                      << "Circuit #" << cid << " established! Shared AES-256 Key: "
                      << color::CYAN << crypto::to_hex(session_key.data(), 8) << "..." << color::RESET
                      << std::endl;

            // Send back CELL_CREATED with our ephemeral public key
            protocol::Cell resp_cell;
            resp_cell.circuit_id = cid;
            resp_cell.command = protocol::CELL_CREATED;
            resp_cell.payload = ephemeral_key.public_key;
            network::send_cell(client_fd, resp_cell);
            continue;
        }

        // Look up circuit
        CircuitContext ctx;
        {
            std::lock_guard<std::mutex> lock(g_circuits_mutex);
            auto it = g_circuits.find(cid);
            if (it == g_circuits.end()) {
                std::cerr << color::RED << "[" << g_name << "] Unknown circuit ID: " << cid << color::RESET << std::endl;
                break;
            }
            ctx = it->second;
        }

        // 2. CELL_RELAY_EXTEND: Extend circuit to next hop
        if (cell.command == protocol::CELL_RELAY_EXTEND) {
            std::vector<uint8_t> decrypted;
            if (!crypto::aes_gcm_decrypt(ctx.session_key, cell.payload, decrypted)) {
                std::cerr << color::RED << "[" << g_name << "] Decryption failed for RELAY_EXTEND on cid " << cid << color::RESET << std::endl;
                break;
            }

            std::string json_str(decrypted.begin(), decrypted.end());
            auto extend_req = json::parse(json_str);

            std::string next_ip = extend_req["next_ip"];
            int next_port = extend_req["next_port"];
            std::string next_client_pubkey_hex = extend_req["client_ephemeral_pubkey"];
            std::vector<uint8_t> next_client_pubkey = crypto::from_hex(next_client_pubkey_hex);

            std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                      << color::B_MAGENTA << "[RELAY_EXTEND] " << color::RESET
                      << "Circuit #" << cid << ": Connecting to next hop at "
                      << color::BOLD << next_ip << ":" << next_port << color::RESET << "..."
                      << std::endl;

            int next_fd = network::connect_to_server(next_ip, next_port);
            if (next_fd < 0) {
                std::cerr << color::RED << "[" << g_name << "] Failed to connect to next hop " << next_ip << ":" << next_port << color::RESET << std::endl;
                break;
            }

            // Send CREATE cell to next hop
            protocol::Cell create_cell;
            create_cell.circuit_id = cid;
            create_cell.command = protocol::CELL_CREATE;
            create_cell.payload = next_client_pubkey;
            if (!network::send_cell(next_fd, create_cell)) {
                close(next_fd);
                break;
            }

            // Wait for CREATED cell from next hop
            protocol::Cell created_cell;
            if (!network::recv_cell(next_fd, created_cell) || created_cell.command != protocol::CELL_CREATED) {
                std::cerr << color::RED << "[" << g_name << "] Did not receive valid CREATED from next hop" << color::RESET << std::endl;
                close(next_fd);
                break;
            }

            // Update circuit context with next_fd
            {
                std::lock_guard<std::mutex> lock(g_circuits_mutex);
                g_circuits[cid].next_fd = next_fd;
            }

            // Start backward reader thread for this circuit
            std::thread(relay_backward_worker, cid, next_fd, client_fd, ctx.session_key).detach();

            std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                      << color::B_GREEN << "[EXTENDED OK] " << color::RESET
                      << "Next hop responded! Relaying encrypted pubkey back to client."
                      << std::endl;

            // Encrypt next hop's CREATED payload under our session key and send back
            std::vector<uint8_t> enc_extended;
            crypto::aes_gcm_encrypt(ctx.session_key, created_cell.payload, enc_extended);

            protocol::Cell ext_resp;
            ext_resp.circuit_id = cid;
            ext_resp.command = protocol::CELL_RELAY_EXTENDED;
            ext_resp.payload = enc_extended;
            network::send_cell(client_fd, ext_resp);
            continue;
        }

        // 3. CELL_RELAY_DATA: Onion Layer Decryption & Forwarding
        if (cell.command == protocol::CELL_RELAY_DATA) {
            std::vector<uint8_t> decrypted;
            if (!crypto::aes_gcm_decrypt(ctx.session_key, cell.payload, decrypted)) {
                std::cerr << color::RED << "[" << g_name << "] Decryption failed for RELAY_DATA on cid " << cid << color::RESET << std::endl;
                break;
            }

            std::string payload_json_str(decrypted.begin(), decrypted.end());
            json payload_obj;
            try {
                payload_obj = json::parse(payload_json_str);
            } catch (...) {
                std::cerr << color::RED << "[" << g_name << "] Failed to parse peeled layer JSON!" << color::RESET << std::endl;
                break;
            }

            std::string ptype = payload_obj.value("type", "");

            if (ptype == "FORWARD") {
                // We peeled an intermediate layer! Forward inner payload to next_fd
                std::string inner_hex = payload_obj["inner_data"];
                std::vector<uint8_t> inner_bytes = crypto::from_hex(inner_hex);

                std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                          << color::B_YELLOW << "[ONION PEEL - LAYER STRIPPED] " << color::RESET
                          << "Circuit #" << cid << ": Peeled outer layer with key "
                          << color::CYAN << crypto::to_hex(ctx.session_key.data(), 4) << "..." << color::RESET
                          << " -> Forwarding inner payload (" << inner_bytes.size() << " bytes) to next hop"
                          << std::endl;

                protocol::Cell fwd_cell;
                fwd_cell.circuit_id = cid;
                fwd_cell.command = protocol::CELL_RELAY_DATA;
                fwd_cell.payload = inner_bytes;

                if (ctx.next_fd < 0 || !network::send_cell(ctx.next_fd, fwd_cell)) {
                    std::cerr << color::RED << "[" << g_name << "] Failed to forward cell to next hop!" << color::RESET << std::endl;
                    break;
                }
            } else if (ptype == "EXTEND") {
                // We are requested to extend the circuit to another relay
                std::string next_ip = payload_obj["next_ip"];
                int next_port = payload_obj["next_port"];
                std::string next_client_pubkey_hex = payload_obj["client_ephemeral_pubkey"];
                std::vector<uint8_t> next_client_pubkey = crypto::from_hex(next_client_pubkey_hex);

                std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                          << color::B_MAGENTA << "[RELAY_EXTEND] " << color::RESET
                          << "Circuit #" << cid << ": Extending circuit to next hop at "
                          << color::BOLD << next_ip << ":" << next_port << color::RESET << "..."
                          << std::endl;

                int next_fd = network::connect_to_server(next_ip, next_port);
                if (next_fd < 0) {
                    std::cerr << color::RED << "[" << g_name << "] Failed to connect to next hop " << next_ip << ":" << next_port << color::RESET << std::endl;
                    break;
                }

                protocol::Cell create_cell;
                create_cell.circuit_id = cid;
                create_cell.command = protocol::CELL_CREATE;
                create_cell.payload = next_client_pubkey;
                if (!network::send_cell(next_fd, create_cell)) {
                    close(next_fd);
                    break;
                }

                protocol::Cell created_cell;
                if (!network::recv_cell(next_fd, created_cell) || created_cell.command != protocol::CELL_CREATED) {
                    std::cerr << color::RED << "[" << g_name << "] Did not receive valid CREATED from next hop" << color::RESET << std::endl;
                    close(next_fd);
                    break;
                }

                {
                    std::lock_guard<std::mutex> lock(g_circuits_mutex);
                    g_circuits[cid].next_fd = next_fd;
                }

                std::thread(relay_backward_worker, cid, next_fd, client_fd, ctx.session_key).detach();

                std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                          << color::B_GREEN << "[EXTENDED OK] " << color::RESET
                          << "Next hop responded! Relaying encrypted pubkey back upstream."
                          << std::endl;

                json ext_resp_obj = {
                    {"type", "EXTENDED"},
                    {"pubkey", crypto::to_hex(created_cell.payload)}
                };
                std::string ext_resp_str = ext_resp_obj.dump();
                std::vector<uint8_t> ext_plain(ext_resp_str.begin(), ext_resp_str.end());
                std::vector<uint8_t> enc_extended;
                crypto::aes_gcm_encrypt(ctx.session_key, ext_plain, enc_extended);

                protocol::Cell ext_resp;
                ext_resp.circuit_id = cid;
                ext_resp.command = protocol::CELL_RELAY_DATA;
                ext_resp.payload = enc_extended;
                network::send_cell(client_fd, ext_resp);
            } else if (ptype == "DEST") {
                // WE ARE THE EXIT RELAY! Final layer peeled!
                std::string dest_ip = payload_obj["dest_ip"];
                int dest_port = payload_obj["dest_port"];
                std::string request_body = payload_obj["body"];

                std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                          << color::B_MAGENTA << "[EXIT NODE PEEL - FINAL LAYER!] " << color::RESET
                          << "Circuit #" << cid << ": All onion layers stripped!"
                          << std::endl;

                std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                          << color::B_GREEN << "[DISPATCHING TO DESTINATION] " << color::RESET
                          << "Connecting to target: " << color::BOLD << dest_ip << ":" << dest_port << color::RESET
                          << " | Request snippet: \"" << color::WHITE
                          << request_body.substr(0, std::min((size_t)40, request_body.length())) << "...\"" << color::RESET
                          << std::endl;

                // Connect to destination server
                int dest_fd = network::connect_to_server(dest_ip, dest_port);
                std::string dest_response = "[ERROR] Could not reach destination server";
                if (dest_fd >= 0) {
                    network::send_exact(dest_fd, request_body.data(), request_body.length());

                    std::vector<char> dest_buf(8192, 0);
                    ssize_t bytes_recvd = recv(dest_fd, dest_buf.data(), dest_buf.size() - 1, 0);
                    if (bytes_recvd > 0) {
                        dest_response = std::string(dest_buf.data(), bytes_recvd);
                    }
                    close(dest_fd);

                    std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                              << color::B_BLUE << "[DESTINATION REPLIED] " << color::RESET
                              << "Received " << dest_response.length() << " bytes from target server."
                              << std::endl;
                }

                // Encrypt response with our Exit session key
                std::vector<uint8_t> plain_resp_bytes(dest_response.begin(), dest_response.end());
                std::vector<uint8_t> enc_resp;
                crypto::aes_gcm_encrypt(ctx.session_key, plain_resp_bytes, enc_resp);

                protocol::Cell resp_cell;
                resp_cell.circuit_id = cid;
                resp_cell.command = protocol::CELL_RELAY_DATA;
                resp_cell.payload = enc_resp;

                std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                          << color::B_CYAN << "[ENCRYPTING RETURN PATH] " << color::RESET
                          << "Sending encrypted response backwards towards client..."
                          << std::endl;

                network::send_cell(client_fd, resp_cell);
            }
        }
    }

    close(client_fd);
}

void register_with_directory(const crypto::KeyPair& id_key) {
    httplib::Client cli(g_dir_addr);
    cli.set_connection_timeout(2, 0);

    json reg_body = {
        {"name", g_name},
        {"role", g_role},
        {"ip", "127.0.0.1"},
        {"port", g_port},
        {"pubkey", id_key.get_public_hex()}
    };

    auto res = cli.Post("/register", reg_body.dump(), "application/json");
    if (res && res->status == 200) {
        std::cout << color::GREEN << "[" << g_name << "] Successfully registered with Directory Authority!" << color::RESET << std::endl;
    } else {
        std::cout << color::YELLOW << "[" << g_name << "] Warning: Directory Authority not responding yet. Will retry in background." << color::RESET << std::endl;
    }

    std::string pubkey_hex = id_key.get_public_hex();

    // Start heartbeat thread
    std::thread([pubkey_hex]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            try {
                httplib::Client cli(g_dir_addr);
                cli.set_connection_timeout(2, 0);
                json hb = {{"ip", "127.0.0.1"}, {"port", g_port}};
                auto res = cli.Post("/heartbeat", hb.dump(), "application/json");
                if (!res || res->status != 200) {
                    // Retry register
                    json reg_body = {
                        {"name", g_name},
                        {"role", g_role},
                        {"ip", "127.0.0.1"},
                        {"port", g_port},
                        {"pubkey", pubkey_hex}
                    };
                    cli.Post("/register", reg_body.dump(), "application/json");
                }
            } catch (...) {}
        }
    }).detach();
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--name" && i + 1 < argc) g_name = argv[++i];
        else if (arg == "--port" && i + 1 < argc) g_port = std::stoi(argv[++i]);
        else if (arg == "--role" && i + 1 < argc) g_role = argv[++i];
        else if (arg == "--dir" && i + 1 < argc) g_dir_addr = argv[++i];
    }

    crypto::KeyPair id_key;

    std::cout << role_color(g_role) << color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  MINI-TOR RELAY NODE: " << std::left << std::setw(38) << g_name << "║\n";
    std::cout << "║  Role: " << std::left << std::setw(12) << g_role << " Port: " << std::left << std::setw(6) << g_port
              << " PubKey: " << id_key.get_public_hex().substr(0, 14) << "... ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << color::RESET << std::endl;

    register_with_directory(id_key);

    g_server_fd = network::create_server_socket(g_port);
    if (g_server_fd < 0) {
        std::cerr << color::RED << "[" << g_name << "] Failed to bind on port " << g_port << color::RESET << std::endl;
        return 1;
    }

    std::cout << color::GREEN << "[" << g_name << "] Listening for onion cells on port " << g_port << "..." << color::RESET << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(g_server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) break;

        std::thread(handle_upstream_connection, client_fd).detach();
    }

    return 0;
}
