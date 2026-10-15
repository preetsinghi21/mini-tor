CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS = -lcrypto

BUILD_DIR = build
SRC_DIR = src

TARGETS = $(BUILD_DIR)/dir_authority \
          $(BUILD_DIR)/relay_node \
          $(BUILD_DIR)/dest_server \
          $(BUILD_DIR)/onion_client

all: $(BUILD_DIR) $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/dir_authority: $(SRC_DIR)/dir_authority.cpp common/*.hpp
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/dir_authority.cpp $(LDFLAGS) -o $@

$(BUILD_DIR)/relay_node: $(SRC_DIR)/relay_node.cpp common/*.hpp
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/relay_node.cpp $(LDFLAGS) -o $@

$(BUILD_DIR)/dest_server: $(SRC_DIR)/dest_server.cpp common/*.hpp
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/dest_server.cpp $(LDFLAGS) -o $@

$(BUILD_DIR)/onion_client: $(SRC_DIR)/onion_client.cpp common/*.hpp
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/onion_client.cpp $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD_DIR) *.log

test: all
	bash test_api.sh

.PHONY: all clean test
