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
    
    bool load(const std::string& filePath);
    bool save(const std::string& filePath);
    
    const Config& get() const;
    void set(const Config& config);
    
    void addRecentFile(const std::string& path);
    
    std::string getLanguage() const;
    void setLanguage(const std::string& lang);
    
    bool shouldCheckUpdates() const;

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    
    Config m_config;
    bool m_loaded = false;
};

}
