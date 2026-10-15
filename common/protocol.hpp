#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include "crypto.hpp"
#include "../third_party/json.hpp"

namespace minitor {
namespace protocol {

using json = nlohmann::json;

enum CellCommand : uint8_t {
    CELL_CREATE         = 0x01, // Client -> First relay to build hop 1
    CELL_CREATED        = 0x02, // Relay -> Client with its ephemeral pubkey
    CELL_RELAY_EXTEND   = 0x03, // Client -> Relay requesting extend to next hop
    CELL_RELAY_EXTENDED = 0x04, // Relay -> Client with next hop's pubkey
    CELL_RELAY_DATA     = 0x05, // Onion routed payload (forward or return)
    CELL_DESTROY        = 0x06  // Tear down circuit
};

inline std::string command_to_string(uint8_t cmd) {
    switch (cmd) {
        case CELL_CREATE: return "CREATE";
        case CELL_CREATED: return "CREATED";
        case CELL_RELAY_EXTEND: return "RELAY_EXTEND";
        case CELL_RELAY_EXTENDED: return "RELAY_EXTENDED";
        case CELL_RELAY_DATA: return "RELAY_DATA";
        case CELL_DESTROY: return "DESTROY";
        default: return "UNKNOWN(" + std::to_string(cmd) + ")";
    }
}

// Wire Cell:
// [ 4 bytes: circuit_id ]
// [ 1 byte:  command    ]
// [ 4 bytes: payload_len]
// [ N bytes: payload    ]
struct Cell {
    uint32_t circuit_id{0};
    uint8_t command{0};
    std::vector<uint8_t> payload;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(9 + payload.size());
        uint32_t net_cid = htonl(circuit_id);
        uint32_t net_len = htonl(static_cast<uint32_t>(payload.size()));

        std::memcpy(buf.data(), &net_cid, 4);
        buf[4] = command;
        std::memcpy(buf.data() + 5, &net_len, 4);
        if (!payload.empty()) {
            std::memcpy(buf.data() + 9, payload.data(), payload.size());
        }
        return buf;
    }

    static bool deserialize(const uint8_t* header9, const uint8_t* payload_data, Cell& out_cell) {
        uint32_t net_cid = 0;
        std::memcpy(&net_cid, header9, 4);
        out_cell.circuit_id = ntohl(net_cid);

        out_cell.command = header9[4];

        uint32_t net_len = 0;
        std::memcpy(&net_len, header9 + 5, 4);
        uint32_t len = ntohl(net_len);

        out_cell.payload.resize(len);
        if (len > 0 && payload_data) {
            std::memcpy(out_cell.payload.data(), payload_data, len);
        }
        return true;
    }
};

// Relay Descriptor for Directory Authority
struct RelayInfo {
    std::string name;
    std::string role; // "guard", "middle", "exit", or "relay"
    std::string ip;
    int port;
    std::string identity_pubkey_hex;
    uint64_t last_heartbeat{0};

    json to_json() const {
        return json{
            {"name", name},
            {"role", role},
            {"ip", ip},
            {"port", port},
            {"pubkey", identity_pubkey_hex},
            {"last_heartbeat", last_heartbeat}
        };
    }

    static RelayInfo from_json(const json& j) {
        RelayInfo r;
        r.name = j.value("name", "");
        r.role = j.value("role", "relay");
        r.ip = j.value("ip", "127.0.0.1");
        r.port = j.value("port", 9001);
        r.identity_pubkey_hex = j.value("pubkey", "");
        r.last_heartbeat = j.value("last_heartbeat", 0ULL);
        return r;
    }
};

} // namespace protocol
} // namespace minitor
