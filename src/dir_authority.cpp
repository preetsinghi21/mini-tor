#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <csignal>
#include <iomanip>

#include "../third_party/httplib.h"
#include "../third_party/json.hpp"
#include "../common/colors.hpp"
#include "../common/protocol.hpp"

using json = nlohmann::json;
using namespace minitor;

std::mutex g_relays_mutex;
std::map<std::string, protocol::RelayInfo> g_relays;
std::unique_ptr<httplib::Server> g_server;

void sig_handler(int) {
    std::cout << "\n" << color::YELLOW << "[DIR_AUTH] Shutting down Directory Authority..." << color::RESET << std::endl;
    if (g_server) g_server->stop();
    exit(0);
}

std::string current_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%H:%M:%S");
    return ss.str();
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int port = 8000;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        }
    }

    std::cout << color::B_CYAN << color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        MINI-TOR DIRECTORY AUTHORITY (CONSENSUS)              ║\n";
    std::cout << "║        Listening on HTTP port: " << std::left << std::setw(30) << port << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << color::RESET << std::endl;

    g_server = std::make_unique<httplib::Server>();

    // Enable CORS for web UI access
    auto set_cors = [](httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
    };

    g_server->Options(".*", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        res.status = 200;
    });

    // 1. Health check
    g_server->Get("/status", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        std::lock_guard<std::mutex> lock(g_relays_mutex);
        json j = {
            {"status", "online"},
            {"active_relays_count", g_relays.size()},
            {"timestamp", current_time()}
        };
        res.set_content(j.dump(2), "application/json");
    });

    // 2. Register Relay
    g_server->Post("/register", [&](const httplib::Request& req, httplib::Response& res) {
        set_cors(res);
        try {
            auto body = json::parse(req.body);
            protocol::RelayInfo info = protocol::RelayInfo::from_json(body);
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            info.last_heartbeat = now_ms;

            std::string key = info.ip + ":" + std::to_string(info.port);

            {
                std::lock_guard<std::mutex> lock(g_relays_mutex);
                g_relays[key] = info;
            }

            std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                      << color::B_GREEN << "[REGISTERED] " << color::RESET
                      << color::BOLD << info.name << color::RESET
                      << " (" << color::YELLOW << info.role << color::RESET << ")"
                      << " at " << color::CYAN << info.ip << ":" << info.port << color::RESET
                      << " | PubKey: " << color::DIM << info.identity_pubkey_hex.substr(0, 16) << "..." << color::RESET
                      << std::endl;

            json resp = {{"status", "registered"}, {"name", info.name}};
            res.set_content(resp.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            json err = {{"error", e.what()}};
            res.set_content(err.dump(), "application/json");
        }
    });

    // 3. Relay Heartbeat
    g_server->Post("/heartbeat", [&](const httplib::Request& req, httplib::Response& res) {
        set_cors(res);
        try {
            auto body = json::parse(req.body);
            std::string ip = body.value("ip", "127.0.0.1");
            int port = body.value("port", 0);
            std::string key = ip + ":" + std::to_string(port);

            std::lock_guard<std::mutex> lock(g_relays_mutex);
            if (g_relays.find(key) != g_relays.end()) {
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                g_relays[key].last_heartbeat = now_ms;
                res.set_content("{\"status\":\"ok\"}", "application/json");
            } else {
                res.status = 404;
                res.set_content("{\"error\":\"relay not registered\"}", "application/json");
            }
        } catch (...) {
            res.status = 400;
        }
    });

    // 4. Client Consensus Query
    g_server->Get("/consensus", [&](const httplib::Request&, httplib::Response& res) {
        set_cors(res);
        std::lock_guard<std::mutex> lock(g_relays_mutex);

        json relay_list = json::array();
        for (const auto& kv : g_relays) {
            relay_list.push_back(kv.second.to_json());
        }

        json resp = {
            {"consensus_version", 1},
            {"timestamp", current_time()},
            {"relays", relay_list}
        };

        std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                  << color::B_BLUE << "[CONSENSUS QUERY] " << color::RESET
                  << "Dispatched directory consensus with "
                  << color::BOLD << relay_list.size() << " active relay(s)" << color::RESET
                  << std::endl;

        res.set_content(resp.dump(2), "application/json");
    });

    std::cout << color::GREEN << "[DIR_AUTH] Directory Authority is active and accepting registrations..." << color::RESET << std::endl;
    g_server->listen("0.0.0.0", port);

    return 0;
}
