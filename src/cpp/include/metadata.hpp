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

    bool load();
    bool isValid() const;
    
    const MetadataHeader& getHeader() const;
    
    MetadataInfo analyze();
    
    std::string readString(uint32_t offset);
    
    std::vector<uint8_t> readData(uint32_t offset, uint32_t size);
    
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

}
