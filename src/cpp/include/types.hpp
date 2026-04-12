#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <variant>

namespace metadata {

// Версии Unity
enum class UnityVersion : uint16_t {
    Unity53 = 16,
    Unity54 = 17,
    Unity55 = 19,
    Unity56 = 20,
    Unity2017_1 = 21,
    Unity2017_2 = 22,
    Unity2017_3 = 23,
    Unity2017_4 = 24,
    Unity2018_1 = 25,
    Unity2018_2 = 26,
    Unity2018_3 = 27,
    Unity2018_4 = 28,
    Unity2019_1 = 29,
    Unity2019_2 = 30,
    Unity2019_3 = 31,
    Unity2019_4 = 32,
    Unity2020_1 = 33,
    Unity2020_2 = 34,
    Unity2020_3 = 35,
    Unity2021_1 = 36,
    Unity2021_2 = 37,
    Unity2021_3 = 38,
    Unity2022_1 = 39,
    Unity2022_2 = 40,
    Unity2022_3 = 41,
    Unity2023_1 = 42,
    Unity2023_2 = 43,
    Unknown = 0
};

// Типы данных метаданных
struct StringLiteral {
    uint32_t offset;
    std::string value;
};

struct TypeDefinition {
    uint32_t flags;
    std::string name;
    std::string namespace_;
    std::string assembly;
    uint32_t typeId;
    uint32_t baseTypeIndex;
    uint32_t elementCount;
    uint32_t rank;
};

struct FieldInfo {
    std::string name;
    std::string type;
    uint32_t offset;
    uint32_t flags;
};

struct MethodInfo {
    std::string name;
    std::string returnType;
    std::vector<std::string> parameters;
    uint32_t flags;
    uint32_t token;
};

struct AssemblyInfo {
    std::string name;
    std::string culture;
    std::vector<uint8_t> publicKey;
    uint32_t version[4];  // major, minor, build, revision
};

// Заголовок метаданных
struct MetadataHeader {
    uint32_t magic;           // 0xF1FA11FA
    uint32_t version;
    uint32_t size;
    uint32_t stringOffset;
    uint32_t stringSize;
    uint32_t eventsOffset;
    uint32_t eventsSize;
    uint32_t propertiesOffset;
    uint32_t propertiesSize;
    uint32_t methodsOffset;
    uint32_t methodsSize;
    uint32_t paramDefsOffset;
    uint32_t paramDefsSize;
    uint32_t fieldsOffset;
    uint32_t fieldsSize;
    uint32_t typesOffset;
    uint32_t typesSize;
    uint32_t assembliesOffset;
    uint32_t assembliesSize;
    uint32_t referencesOffset;
    uint32_t referencesSize;
    uint32_t tablesOffset;
    uint32_t tablesSize;
};

// Результат анализа
struct MetadataInfo {
    std::string filePath;
    bool isEncrypted;
    std::optional<UnityVersion> unityVersion;
    std::vector<AssemblyInfo> assemblies;
    std::vector<TypeDefinition> types;
    std::vector<FieldInfo> fields;
    std::vector<MethodInfo> methods;
    std::vector<StringLiteral> strings;
    size_t fileSize;
    std::string errorMessage;
};

// Константы
constexpr uint32_t METADATA_MAGIC = 0xF1FA11FA;
constexpr uint8_t METADATA_SIGNATURE[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

} // namespace metadata
