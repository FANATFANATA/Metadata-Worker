#pragma once

#include <string>
#include <map>

namespace i18n {

// Поддерживаемые языки
enum class Language {
    English,
    Russian
};

class LocalizationManager {
public:
    static LocalizationManager& instance();
    
    // Установка языка
    void setLanguage(Language lang);
    void setLanguage(const std::string& langCode);
    
    // Получение строки
    std::string get(const std::string& key) const;
    
    // Загрузка локали из файла
    bool loadFromJson(const std::string& filePath);
    
    // Получение текущего языка
    Language getCurrentLanguage() const;
    
    // Код текущего языка
    std::string getCurrentLanguageCode() const;

private:
    LocalizationManager();
    ~LocalizationManager();
    
    Language m_currentLanguage = Language::English;
    std::map<std::string, std::map<std::string, std::string>> m_translations;
    
    void loadDefaultTranslations();
};

// Удобные функции
void setLanguage(const std::string& langCode);
std::string tr(const std::string& key);

} // namespace i18n
