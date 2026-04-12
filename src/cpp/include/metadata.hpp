#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <functional>

namespace metadata {

class MetadataReader {
public:
    explicit MetadataReader(const std::string& filePath);
    ~MetadataReader();

    // Загрузка файла
    bool load();
    
    // Проверка валидности
    bool isValid() const;
    
    // Получение заголовка
    const MetadataHeader& getHeader() const;
    
    // Получение информации о метаданных
    MetadataInfo analyze();
    
    // Чтение строк
    std::string readString(uint32_t offset);
    
    // Чтение данных
    std::vector<uint8_t> readData(uint32_t offset, uint32_t size);
    
    // Проверка на зашифрованность
    bool isEncrypted() const;

private:
    std::string m_filePath;
    std::vector<uint8_t> m_data;
    MetadataHeader m_header;
    bool m_loaded = false;
    bool m_valid = false;
    
    bool parseHeader();
    bool validateMagic();
};

} // namespace metadata
