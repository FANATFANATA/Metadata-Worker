#include "i18n.hpp"
#include <iostream>

namespace i18n {

LocalizationManager::LocalizationManager() {
    loadDefaultTranslations();
}

LocalizationManager::~LocalizationManager() = default;

LocalizationManager& LocalizationManager::instance() {
    static LocalizationManager instance;
    return instance;
}

void LocalizationManager::loadDefaultTranslations() {
    
    m_translations["en"]["banner"] = R"(
  __  __ _     _     _               _                   ____  _             _    
 |  \/  (_) __| | __| |_   _ _ __ __| |_ __ ___  _ __   / ___|(_)_ __ ___ __| |_  
 | |\/| | |/ _| |/ _| | | | | '__/ _| | '__/ _ \| '_ \  \___ \| | '__/ __/ _| | | 
 | |  | | | (_| | (__| | |_| | | | (_| | | | (_) | | | |  ___) | | | | (_| (_| | | 
 |_|  |_|_|\__,_|\__|_|\__,_|_|  \__|_|_|  \___/|_| |_| |____/|_|_|  \___\__,_|_| 
                                                                                  
)";
    m_translations["en"]["path_to_file"] = "Enter path to file (or 'q' to quit): ";
    m_translations["en"]["path_to_save"] = "Enter path to save: ";
    m_translations["en"]["path_to_folder"] = "Enter path to folder: ";
    m_translations["en"]["file_not_found"] = "Error: File not found!";
    m_translations["en"]["folder_not_found"] = "Error: Folder not found!";
    m_translations["en"]["enter_path"] = "Error: Please enter a path!";
    m_translations["en"]["decrypt_success"] = "Successfully decrypted!";
    m_translations["en"]["decrypt_error"] = "Decryption failed!";
    m_translations["en"]["invalid_file"] = "Invalid metadata file!";
    m_translations["en"]["unity_version"] = "Unity version: ";
    m_translations["en"]["encrypted"] = "Encrypted: ";
    m_translations["en"]["yes"] = "Yes";
    m_translations["en"]["no"] = "No";
    m_translations["en"]["file_size"] = "File size: ";
    m_translations["en"]["menu_title"] = "\n=== Metadata Worker Menu ===";
    m_translations["en"]["select_file"] = "1. Select file";
    m_translations["en"]["decrypt_file"] = "2. Decrypt file";
    m_translations["en"]["analyze_file"] = "3. Analyze file";
    m_translations["en"]["exit"] = "0. Exit";
    m_translations["en"]["choose_option"] = "Choose option: ";
    
    
    m_translations["ru"]["banner"] = R"(
  __  __ _     _     _               _                   ____  _             _    
 |  \/  (_) __| | __| |_   _ _ __ __| |_ __ ___  _ __   / ___|(_)_ __ ___ __| |_  
 | |\/| | |/ _| |/ _| | | | | '__/ _| | '__/ _ \| '_ \  \___ \| | '__/ __/ _| | | 
 | |  | | | (_| | (__| | |_| | | | (_| | | | (_) | | | |  ___) | | | | (_| (_| | | 
 |_|  |_|_|\__,_|\__|_|\__,_|_|  \__|_|_|  \___/|_| |_| |____/|_|_|  \___\__,_|_| 
                                                                                  
)";
    m_translations["ru"]["path_to_file"] = "Введите путь к файлу (или 'q' для выхода): ";
    m_translations["ru"]["path_to_save"] = "Введите путь для сохранения: ";
    m_translations["ru"]["path_to_folder"] = "Введите путь к папке: ";
    m_translations["ru"]["file_not_found"] = "Ошибка: Файл не найден!";
    m_translations["ru"]["folder_not_found"] = "Ошибка: Папка не найдена!";
    m_translations["ru"]["enter_path"] = "Ошибка: Введите путь!";
    m_translations["ru"]["decrypt_success"] = "Успешно расшифровано!";
    m_translations["ru"]["decrypt_error"] = "Расшифровка не удалась!";
    m_translations["ru"]["invalid_file"] = "Неверный файл метаданных!";
    m_translations["ru"]["unity_version"] = "Версия Unity: ";
    m_translations["ru"]["encrypted"] = "Зашифровано: ";
    m_translations["ru"]["yes"] = "Да";
    m_translations["ru"]["no"] = "Нет";
    m_translations["ru"]["file_size"] = "Размер файла: ";
    m_translations["ru"]["menu_title"] = "\n=== Metadata Worker Меню ===";
    m_translations["ru"]["select_file"] = "1. Выбрать файл";
    m_translations["ru"]["decrypt_file"] = "2. Расшифровать файл";
    m_translations["ru"]["analyze_file"] = "3. Анализировать файл";
    m_translations["ru"]["exit"] = "0. Выход";
    m_translations["ru"]["choose_option"] = "Выберите опцию: ";
}

void LocalizationManager::setLanguage(Language lang) {
    m_currentLanguage = lang;
}

void LocalizationManager::setLanguage(const std::string& langCode) {
    if (langCode == "ru") {
        m_currentLanguage = Language::Russian;
    } else {
        m_currentLanguage = Language::English;
    }
}

std::string LocalizationManager::get(const std::string& key) const {
    std::string langCode = getCurrentLanguageCode();
    auto langIt = m_translations.find(langCode);
    if (langIt != m_translations.end()) {
        auto keyIt = langIt->second.find(key);
        if (keyIt != langIt->second.end()) {
            return keyIt->second;
        }
    }
    
    auto enIt = m_translations.find("en");
    if (enIt != m_translations.end()) {
        auto keyIt = enIt->second.find(key);
        if (keyIt != enIt->second.end()) {
            return keyIt->second;
        }
    }
    
    return key;
}

Language LocalizationManager::getCurrentLanguage() const {
    return m_currentLanguage;
}

std::string LocalizationManager::getCurrentLanguageCode() const {
    switch (m_currentLanguage) {
        case Language::Russian: return "ru";
        default: return "en";
    }
}

void setLanguage(const std::string& langCode) {
    LocalizationManager::instance().setLanguage(langCode);
}

std::string tr(const std::string& key) {
    return LocalizationManager::instance().get(key);
}

}
