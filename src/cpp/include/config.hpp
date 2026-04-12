#pragma once

#include <string>
#include <map>
#include <vector>

namespace config {

struct Config {
    std::string language = "en";
    std::string theme = "default";
    std::vector<std::string> recentFiles;
    std::string lastOutputDir;
    bool checkUpdates = true;
};

class ConfigManager {
public:
    static ConfigManager& instance();
    
    // Загрузка конфигурации
    bool load(const std::string& filePath);
    
    // Сохранение конфигурации
    bool save(const std::string& filePath);
    
    // Получение значения
    const Config& get() const;
    
    // Установка значения
    void set(const Config& config);
    
    // Добавление недавнего файла
    void addRecentFile(const std::string& path);
    
    // Получение языка
    std::string getLanguage() const;
    
    // Установка языка
    void setLanguage(const std::string& lang);
    
    // Проверка обновлений
    bool shouldCheckUpdates() const;

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    
    Config m_config;
    bool m_loaded = false;
};

} // namespace config
