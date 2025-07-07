#include "../includes/Logger.hpp"

void Logger::log(const std::string& message) {
    std::cout << "[LOG] " << message << std::endl;
}

void Logger::error(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
}
