#include "config.hpp"
#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

// Простой JSON парсер (можно заменить на nlohmann/json)
namespace {

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

bool parseJsonString(const std::string& json, config::Config& cfg) {
    // Очень упрощенный парсер JSON
    auto findValue = [&](const std::string& key) -> std::string {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return "";
        
        pos = json.find(':', pos);
        if (pos == std::string::npos) return "";
        pos++;
        
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        
        if (pos >= json.size()) return "";
        
        if (json[pos] == '"') {
            size_t start = pos + 1;
            size_t end = json.find('"', start);
            if (end == std::string::npos) return "";
            return json.substr(start, end - start);
        } else if (json[pos] == 't' || json[pos] == 'f') {
            return json.substr(pos, 4);
        } else if (json[pos] == '[') {
            size_t end = json.find(']', pos);
            if (end == std::string::npos) return "";
            return json.substr(pos, end - pos + 1);
        }
        
        return "";
    };
    
    std::string lang = findValue("language");
    if (!lang.empty()) cfg.language = lang;
    
    std::string theme = findValue("theme");
    if (!theme.empty()) cfg.theme = theme;
    
    std::string checkUpdates = findValue("check_updates");
    cfg.checkUpdates = (checkUpdates == "true");
    
    std::string lastDir = findValue("last_output_dir");
    if (!lastDir.empty()) cfg.lastOutputDir = lastDir;
    
    // Парсинг массива recent_files
    std::string recentStr = findValue("recent_files");
    if (!recentStr.empty() && recentStr[0] == '[') {
        size_t pos = 1;
        while (pos < recentStr.size()) {
            size_t start = recentStr.find('"', pos);
            if (start == std::string::npos) break;
            size_t end = recentStr.find('"', start + 1);
            if (end == std::string::npos) break;
            
            cfg.recentFiles.push_back(recentStr.substr(start + 1, end - start - 1));
            pos = end + 1;
        }
    }
    
    return true;
}

std::string toJson(const config::Config& cfg) {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"language\": \"" << cfg.language << "\",\n";
    oss << "  \"theme\": \"" << cfg.theme << "\",\n";
    oss << "  \"check_updates\": " << (cfg.checkUpdates ? "true" : "false") << ",\n";
    oss << "  \"last_output_dir\": \"" << cfg.lastOutputDir << "\",\n";
    oss << "  \"recent_files\": [";
    
    for (size_t i = 0; i < cfg.recentFiles.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "\"" << cfg.recentFiles[i] << "\"";
    }
    
    oss << "]\n";
    oss << "}\n";
    
    return oss.str();
}

} // anonymous namespace

namespace config {

ConfigManager& ConfigManager::instance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::load(const std::string& filePath) {
    if (!utils::fileExists(filePath)) {
        return false;
    }
    
    std::string content = utils::readFileAsString(filePath);
    if (content.empty()) {
        return false;
    }
    
    parseJsonString(content, m_config);
    m_loaded = true;
    return true;
}

bool ConfigManager::save(const std::string& filePath) {
    std::string json = toJson(m_config);
    return utils::writeFileFromString(filePath, json);
}

const Config& ConfigManager::get() const {
    return m_config;
}

void ConfigManager::set(const Config& config) {
    m_config = config;
}

void ConfigManager::addRecentFile(const std::string& path) {
    // Удаляем если уже есть
    auto it = std::find(m_config.recentFiles.begin(), m_config.recentFiles.end(), path);
    if (it != m_config.recentFiles.end()) {
        m_config.recentFiles.erase(it);
    }
    
    // Добавляем в начало
    m_config.recentFiles.insert(m_config.recentFiles.begin(), path);
    
    // Ограничиваем до 10 файлов
    if (m_config.recentFiles.size() > 10) {
        m_config.recentFiles.resize(10);
    }
}

std::string ConfigManager::getLanguage() const {
    return m_config.language;
}

void ConfigManager::setLanguage(const std::string& lang) {
    m_config.language = lang;
}

bool ConfigManager::shouldCheckUpdates() const {
    return m_config.checkUpdates;
}

} // namespace config
