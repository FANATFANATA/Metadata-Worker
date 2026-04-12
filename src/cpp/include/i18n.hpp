#pragma once

#include <string>
#include <map>

namespace i18n {

enum class Language {
    English,
    Russian
};

class LocalizationManager {
public:
    static LocalizationManager& instance();
    
    void setLanguage(Language lang);
    void setLanguage(const std::string& langCode);
    
    std::string get(const std::string& key) const;
    
    bool loadFromJson(const std::string& filePath);
    
    Language getCurrentLanguage() const;
    
    std::string getCurrentLanguageCode() const;

private:
    LocalizationManager();
    ~LocalizationManager();
    
    Language m_currentLanguage = Language::English;
    std::map<std::string, std::map<std::string, std::string>> m_translations;
    
    void loadDefaultTranslations();
};

void setLanguage(const std::string& langCode);
std::string tr(const std::string& key);

}
