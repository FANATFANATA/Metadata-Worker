#include "utils.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace utils {

std::string resolvePath(const std::string& path) {
    if (path.empty()) return "";
    
    std::filesystem::path p(path);
    if (p.is_absolute()) {
        return p.lexically_normal().string();
    } else {
        return std::filesystem::current_path().append(p).lexically_normal().string();
    }
}

bool fileExists(const std::string& path) {
    try {
        return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
    } catch (...) {
        return false;
    }
}

bool directoryExists(const std::string& path) {
    try {
        return std::filesystem::exists(path) && std::filesystem::is_directory(path);
    } catch (...) {
        return false;
    }
}

std::string getDirectoryName(const std::string& path) {
    return std::filesystem::path(path).parent_path().string();
}

std::string getFileName(const std::string& path) {
    return std::filesystem::path(path).filename().string();
}

std::string getExtension(const std::string& path) {
    return std::filesystem::path(path).extension().string();
}

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return {};
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return {};
    }
    
    return buffer;
}

bool writeFile(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

std::string readFileAsString(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

bool writeFileFromString(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    file << content;
    return file.good();
}

bool validatePath(const std::string& path, bool mustExist) {
    if (path.empty()) {
        return false;
    }
    
    if (mustExist) {
        return fileExists(path);
    } else {
        // Проверяем существование родительской директории
        std::string dir = getDirectoryName(path);
        return dir.empty() || directoryExists(dir);
    }
}

void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

std::string promptInput(const std::string& message) {
    std::cout << message;
    std::string input;
    std::getline(std::cin, input);
    return input;
}

std::string selectFileFromRecent(const std::vector<std::string>& recentFiles) {
    if (recentFiles.empty()) {
        return "";
    }
    
    std::cout << "\nRecent files:\n";
    for (size_t i = 0; i < std::min(recentFiles.size(), size_t(5)); ++i) {
        std::cout << "  [" << (i + 1) << "] " << recentFiles[i] << "\n";
    }
    
    std::string input = promptInput("Select file number or enter path: ");
    
    if (input.empty()) {
        return "";
    }
    
    // Проверка на номер
    if (input.length() == 1 && input[0] >= '1' && input[0] <= '5') {
        size_t index = input[0] - '1';
        if (index < recentFiles.size()) {
            return recentFiles[index];
        }
    }
    
    // Возвращаем как путь
    return input;
}

std::string formatFileSize(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unitIndex = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unitIndex < 3) {
        size /= 1024.0;
        unitIndex++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
    return oss.str();
}

std::string formatDateTime(time_t time) {
    std::tm* tm_info = std::localtime(&time);
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buffer);
}

// Простая реализация MD5 (можно заменить на OpenSSL или другую библиотеку)
std::string md5Hash(const std::vector<uint8_t>& data) {
    // Заглушка - в реальной реализации использовать криптографическую библиотеку
    std::ostringstream oss;
    oss << "md5_" << data.size();
    return oss.str();
}

std::string sha1Hash(const std::vector<uint8_t>& data) {
    // Заглушка - в реальной реализации использовать криптографическую библиотеку
    std::ostringstream oss;
    oss << "sha1_" << data.size();
    return oss.str();
}

} // namespace utils
