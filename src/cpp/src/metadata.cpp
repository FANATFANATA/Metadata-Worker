#include "metadata.hpp"
#include "types.hpp"
#include "utils.hpp"
#include <fstream>
#include <cstring>
#include <iostream>

namespace metadata {

MetadataReader::MetadataReader(const std::string& filePath)
    : m_filePath(filePath) {
}

MetadataReader::~MetadataReader() = default;

bool MetadataReader::load() {
    if (!utils::fileExists(m_filePath)) {
        std::cerr << "File does not exist: " << m_filePath << std::endl;
        return false;
    }
    
    m_data = utils::readFile(m_filePath);
    if (m_data.empty()) {
        std::cerr << "Failed to read file or file is empty: " << m_filePath << std::endl;
        return false;
    }
    
    if (!parseHeader()) {
        std::cerr << "Failed to parse header" << std::endl;
        return false;
    }
    
    m_loaded = true;
    m_valid = validateMagic();
    return m_valid;
}

bool MetadataReader::isValid() const {
    return m_valid && m_loaded;
}

const MetadataHeader& MetadataReader::getHeader() const {
    return m_header;
}

bool MetadataReader::parseHeader() {
    if (m_data.size() < sizeof(MetadataHeader)) {
        return false;
    }
    
    if (m_data.size() < 56) {
        return false;
    }
    
    m_header.magic = *reinterpret_cast<const uint32_t*>(&m_data[0]);
    m_header.version = *reinterpret_cast<const uint32_t*>(&m_data[4]);
    m_header.size = *reinterpret_cast<const uint32_t*>(&m_data[8]);
    
    return true;
}

bool MetadataReader::validateMagic() {
    return m_header.magic == METADATA_MAGIC;
}

MetadataInfo MetadataReader::analyze() {
    MetadataInfo info;
    info.filePath = m_filePath;
    info.fileSize = m_data.size();
    info.isEncrypted = isEncrypted();
    
    if (!m_valid) {
        info.errorMessage = "Invalid metadata file";
        return info;
    }
    
    uint16_t version = static_cast<uint16_t>(m_header.version & 0xFFFF);
    switch (version) {
        case 16: info.unityVersion = UnityVersion::Unity53; break;
        case 17: info.unityVersion = UnityVersion::Unity54; break;
        case 19: info.unityVersion = UnityVersion::Unity55; break;
        case 20: info.unityVersion = UnityVersion::Unity56; break;
        case 21: info.unityVersion = UnityVersion::Unity2017_1; break;
        case 22: info.unityVersion = UnityVersion::Unity2017_2; break;
        case 23: info.unityVersion = UnityVersion::Unity2017_3; break;
        case 24: info.unityVersion = UnityVersion::Unity2017_4; break;
        case 25: info.unityVersion = UnityVersion::Unity2018_1; break;
        case 26: info.unityVersion = UnityVersion::Unity2018_2; break;
        case 27: info.unityVersion = UnityVersion::Unity2018_3; break;
        case 28: info.unityVersion = UnityVersion::Unity2018_4; break;
        case 29: info.unityVersion = UnityVersion::Unity2019_1; break;
        case 30: info.unityVersion = UnityVersion::Unity2019_2; break;
        case 31: info.unityVersion = UnityVersion::Unity2019_3; break;
        case 32: info.unityVersion = UnityVersion::Unity2019_4; break;
        case 33: info.unityVersion = UnityVersion::Unity2020_1; break;
        case 34: info.unityVersion = UnityVersion::Unity2020_2; break;
        case 35: info.unityVersion = UnityVersion::Unity2020_3; break;
        case 36: info.unityVersion = UnityVersion::Unity2021_1; break;
        case 37: info.unityVersion = UnityVersion::Unity2021_2; break;
        case 38: info.unityVersion = UnityVersion::Unity2021_3; break;
        case 39: info.unityVersion = UnityVersion::Unity2022_1; break;
        case 40: info.unityVersion = UnityVersion::Unity2022_2; break;
        case 41: info.unityVersion = UnityVersion::Unity2022_3; break;
        case 42: info.unityVersion = UnityVersion::Unity2023_1; break;
        case 43: info.unityVersion = UnityVersion::Unity2023_2; break;
        default: info.unityVersion = UnityVersion::Unknown; break;
    }
    
    return info;
}

std::string MetadataReader::readString(uint32_t offset) {
    if (offset >= m_data.size()) {
        return "";
    }
    
    const char* str = reinterpret_cast<const char*>(&m_data[offset]);
    size_t maxLen = m_data.size() - offset;
    size_t len = strnlen(str, maxLen);
    
    return std::string(str, len);
}

std::vector<uint8_t> MetadataReader::readData(uint32_t offset, uint32_t size) {
    if (offset + size > m_data.size()) {
        return {};
    }
    
    return std::vector<uint8_t>(m_data.begin() + offset, m_data.begin() + offset + size);
}

bool MetadataReader::isEncrypted() const {
    if (!m_valid || m_data.size() < 12) {
        return false;
    }
    
    for (int i = 0; i < 12; ++i) {
        if (m_data[i] != METADATA_SIGNATURE[i]) {
            return true;
        }
    }
    
    return false;
}

}
