#pragma once

#include <string>
#include <vector>
#include <filesystem>

namespace utils {

// Работа с путями
std::string resolvePath(const std::string& path);
bool fileExists(const std::string& path);
bool directoryExists(const std::string& path);
std::string getDirectoryName(const std::string& path);
std::string getFileName(const std::string& path);
std::string getExtension(const std::string& path);

// Работа с файлами
std::vector<uint8_t> readFile(const std::string& path);
bool writeFile(const std::string& path, const std::vector<uint8_t>& data);
std::string readFileAsString(const std::string& path);
bool writeFileFromString(const std::string& path, const std::string& content);

// Валидация путей
bool validatePath(const std::string& path, bool mustExist = true);

// Консольный ввод/вывод
void clearScreen();
std::string promptInput(const std::string& message);
std::string selectFileFromRecent(const std::vector<std::string>& recentFiles);

// Форматирование
std::string formatFileSize(size_t bytes);
std::string formatDateTime(time_t time);

// Хэширование
std::string md5Hash(const std::vector<uint8_t>& data);
std::string sha1Hash(const std::vector<uint8_t>& data);

} // namespace utils
