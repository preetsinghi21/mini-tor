#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/colors.hpp"
#include "../common/network.hpp"

using namespace minitor;

int g_server_fd = -1;

void sig_handler(int) {
    std::cout << "\n" << color::YELLOW << "[DEST_SERVER] Shutting down..." << color::RESET << std::endl;
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

void handle_client(int client_fd, sockaddr_in client_addr) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    int port = ntohs(client_addr.sin_port);

    std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
              << color::B_GREEN << "[NEW CONNECTION] " << color::RESET
              << "Inbound TCP connection from "
              << color::BOLD << color::B_MAGENTA << ip_str << ":" << port << color::RESET
              << " (" << color::YELLOW << "Exit Relay Node" << color::RESET << ")"
              << std::endl;

    std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
              << color::B_CYAN << "[PRIVACY CHECK] " << color::RESET
              << "Notice: " << color::BOLD << "Destination server has ZERO knowledge of the original client's IP!" << color::RESET
              << std::endl;

    // Read payload
    std::vector<char> buffer(4096, 0);
    ssize_t bytes_read = recv(client_fd, buffer.data(), buffer.size() - 1, 0);
    if (bytes_read > 0) {
        std::string request(buffer.data(), bytes_read);

        std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                  << color::B_YELLOW << "[PAYLOAD RECEIVED (" << bytes_read << " bytes)]: " << color::RESET
                  << color::WHITE << request << color::RESET
                  << std::endl;

        std::string response_body = "[ACK FROM DESTINATION SERVER] Hello! Your request was received safely. "
                                    "Connected Peer IP was: " + std::string(ip_str) + ":" + std::to_string(port) +
                                    " (Exit Node). Client IP was completely obscured.";

        std::string http_response;
        if (request.find("GET") != std::string::npos || request.find("POST") != std::string::npos) {
            http_response = "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain\r\n"
                            "Content-Length: " + std::to_string(response_body.length()) + "\r\n"
                            "Connection: close\r\n\r\n" + response_body;
        } else {
            http_response = response_body;
        }

        network::send_exact(client_fd, http_response.data(), http_response.length());
        std::cout << color::DIM << "[" << current_time() << "] " << color::RESET
                  << color::B_BLUE << "[RESPONSE SENT] " << color::RESET
                  << "Sent " << http_response.length() << " bytes back to Exit Node."
                  << std::endl;
    }

    close(client_fd);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int port = 9090;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        }
    }

    std::cout << color::B_MAGENTA << color::BOLD;
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║        DESTINATION TARGET SERVER (MOCK WEB / ECHO)           ║\n";
    std::cout << "║        Listening on Port: " << std::left << std::setw(34) << port << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << color::RESET << std::endl;

    g_server_fd = network::create_server_socket(port);
    if (g_server_fd < 0) {
        std::cerr << color::RED << "[DEST_SERVER] Failed to bind to port " << port << color::RESET << std::endl;
        return 1;
    }

    std::cout << color::GREEN << "[DEST_SERVER] Waiting for connections from Exit Relays..." << color::RESET << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(g_server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) break;

        std::thread(handle_client, client_fd, client_addr).detach();
    }

    return 0;
}
