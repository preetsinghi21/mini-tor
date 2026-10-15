#pragma once
#include <string>

namespace minitor {
namespace color {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string DIM     = "\033[2m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";

    // Bright colors
    const std::string B_RED     = "\033[91m";
    const std::string B_GREEN   = "\033[92m";
    const std::string B_YELLOW  = "\033[93m";
    const std::string B_BLUE    = "\033[94m";
    const std::string B_MAGENTA = "\033[95m";
    const std::string B_CYAN    = "\033[96m";
    const std::string B_WHITE   = "\033[97m";

    // Backgrounds
    const std::string BG_DARK   = "\033[40m";
    const std::string BG_BLUE   = "\033[44m";
    const std::string BG_MAGENTA= "\033[45m";
}
}
