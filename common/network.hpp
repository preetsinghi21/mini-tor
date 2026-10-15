#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "protocol.hpp"

namespace minitor {
namespace network {

inline bool send_exact(int fd, const void* data, size_t len) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = ::send(fd, ptr + total_sent, len - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += sent;
    }
    return true;
}

inline bool recv_exact(int fd, void* data, size_t len) {
    uint8_t* ptr = static_cast<uint8_t*>(data);
    size_t total_recv = 0;
    while (total_recv < len) {
        ssize_t recvd = ::recv(fd, ptr + total_recv, len - total_recv, 0);
        if (recvd <= 0) return false;
        total_recv += recvd;
    }
    return true;
}

inline bool send_cell(int fd, const protocol::Cell& cell) {
    std::vector<uint8_t> bytes = cell.serialize();
    return send_exact(fd, bytes.data(), bytes.size());
}

inline bool recv_cell(int fd, protocol::Cell& cell) {
    uint8_t header[9];
    if (!recv_exact(fd, header, 9)) {
        return false;
    }

    uint32_t net_len = 0;
    std::memcpy(&net_len, header + 5, 4);
    uint32_t payload_len = ntohl(net_len);

    std::vector<uint8_t> payload_buf(payload_len);
    if (payload_len > 0) {
        if (!recv_exact(fd, payload_buf.data(), payload_len)) {
            return false;
        }
    }

    return protocol::Cell::deserialize(header, payload_buf.data(), cell);
}

inline int create_server_socket(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return -1;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 128) < 0) {
        close(server_fd);
        return -1;
    }

    return server_fd;
}

inline int connect_to_server(const std::string& ip, int port) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) return -1;

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
        close(sock_fd);
        return -1;
    }

    if (connect(sock_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

} // namespace network
} // namespace minitor
