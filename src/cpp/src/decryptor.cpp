#include "decryptor.hpp"
#include <algorithm>
#include <cstring>

namespace metadata {

Decryptor::Decryptor() {
    // Регистрация методов дешифровки
    registerMethod("xor_simple", "Simple XOR with single byte key", 
        [](std::vector<uint8_t>& data) { return xorDecrypt(data, {0x53}); });
    
    registerMethod("xor_alt", "Alternative XOR with 0xA3 key",
        [](std::vector<uint8_t>& data) { return xorDecrypt(data, {0xA3}); });
    
    registerMethod("xor_2byte", "XOR with 2-byte key",
        [](std::vector<uint8_t>& data) { return xorDecrypt(data, {0x12, 0x34}); });
    
    registerMethod("xor_4byte", "XOR with 4-byte key",
        [](std::vector<uint8_t>& data) { return xorDecrypt(data, {0xFF, 0xFF, 0xFF, 0xFF}); });
    
    registerMethod("rot1", "ROT shift by 1",
        [](std::vector<uint8_t>& data) { return rotDecrypt(data, 1); });
    
    registerMethod("custom1", "Custom decrypt method 1", customDecrypt1);
    registerMethod("custom2", "Custom decrypt method 2", customDecrypt2);
    registerMethod("custom3", "Custom decrypt method 3", customDecrypt3);
    registerMethod("custom4", "Custom decrypt method 4", customDecrypt4);
    registerMethod("custom5", "Custom decrypt method 5", customDecrypt5);
    registerMethod("custom6", "Custom decrypt method 6", customDecrypt6);
    registerMethod("custom7", "Custom decrypt method 7", customDecrypt7);
    registerMethod("custom8", "Custom decrypt method 8", customDecrypt8);
    registerMethod("custom9", "Custom decrypt method 9", customDecrypt9);
    registerMethod("custom10", "Custom decrypt method 10", customDecrypt10);
    registerMethod("custom11", "Custom decrypt method 11", customDecrypt11);
    registerMethod("custom12", "Custom decrypt method 12", customDecrypt12);
    registerMethod("custom13", "Custom decrypt method 13", customDecrypt13);
    registerMethod("custom14", "Custom decrypt method 14", customDecrypt14);
    registerMethod("custom15", "Custom decrypt method 15", customDecrypt15);
    registerMethod("custom16", "Custom decrypt method 16", customDecrypt16);
    registerMethod("custom17", "Custom decrypt method 17", customDecrypt17);
    registerMethod("custom18", "Custom decrypt method 18", customDecrypt18);
    registerMethod("custom19", "Custom decrypt method 19", customDecrypt19);
    registerMethod("custom20", "Custom decrypt method 20", customDecrypt20);
}

Decryptor::~Decryptor() = default;

void Decryptor::registerMethod(const std::string& name, 
                               const std::string& description,
                               DecryptFunc func) {
    m_methods[name] = {name, description, func};
}

bool Decryptor::tryDecrypt(std::vector<uint8_t>& data, const std::string& methodName) {
    auto it = m_methods.find(methodName);
    if (it == m_methods.end()) {
        return false;
    }
    
    std::vector<uint8_t> copy = data;
    if (it->second.func(copy)) {
        if (validateDecryption(copy)) {
            data = std::move(copy);
            return true;
        }
    }
    
    return false;
}

bool Decryptor::autoDecrypt(std::vector<uint8_t>& data) {
    for (auto& [name, method] : m_methods) {
        std::vector<uint8_t> copy = data;
        if (method.func(copy)) {
            if (validateDecryption(copy)) {
                data = std::move(copy);
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> Decryptor::getAvailableMethods() const {
    std::vector<std::string> methods;
    for (const auto& [name, _] : m_methods) {
        methods.push_back(name);
    }
    return methods;
}

bool Decryptor::xorDecrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    if (key.empty()) {
        return false;
    }
    
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % key.size()];
    }
    
    return true;
}

bool Decryptor::rotDecrypt(std::vector<uint8_t>& data, uint8_t shift) {
    for (auto& byte : data) {
        byte = ((byte - shift) & 0xFF);
    }
    return true;
}

// Заглушки для кастомных методов дешифровки
// В реальной реализации здесь будет логика из Python-версии
bool Decryptor::customDecrypt1(std::vector<uint8_t>& data) {
    // TODO: Implement from Python source
    (void)data;
    return false;
}

bool Decryptor::customDecrypt2(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt3(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt4(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt5(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt6(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt7(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt8(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt9(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt10(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt11(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt12(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt13(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt14(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt15(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt16(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt17(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt18(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt19(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::customDecrypt20(std::vector<uint8_t>& data) {
    (void)data;
    return false;
}

bool Decryptor::validateDecryption(const std::vector<uint8_t>& data) {
    if (data.size() < 12) {
        return false;
    }
    
    // Проверка на правильную сигнатуру после дешифровки
    for (int i = 0; i < 12; ++i) {
        if (data[i] != METADATA_SIGNATURE[i]) {
            return false;
        }
    }
    
    // Проверка magic bytes
    if (data.size() >= 4) {
        uint32_t magic = *reinterpret_cast<const uint32_t*>(&data[0]);
        if (magic != METADATA_MAGIC) {
            return false;
        }
    }
    
    return true;
}

} // namespace metadata
