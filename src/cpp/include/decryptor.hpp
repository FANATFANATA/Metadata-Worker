#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <functional>
#include <map>

namespace metadata {

// Типы функций дешифровки
using DecryptFunc = std::function<bool(std::vector<uint8_t>&)>;

// Информация о методе дешифровки
struct DecryptMethod {
    std::string name;
    std::string description;
    DecryptFunc func;
};

class Decryptor {
public:
    Decryptor();
    ~Decryptor();

    // Регистрация метода дешифровки
    void registerMethod(const std::string& name, 
                       const std::string& description,
                       DecryptFunc func);
    
    // Дешифровка данными методами
    bool tryDecrypt(std::vector<uint8_t>& data, const std::string& methodName);
    
    // Автоопределение и дешифровка
    bool autoDecrypt(std::vector<uint8_t>& data);
    
    // Получение списка доступных методов
    std::vector<std::string> getAvailableMethods() const;
    
    // Статические методы дешифровки
    static bool xorDecrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    static bool rotDecrypt(std::vector<uint8_t>& data, uint8_t shift);
    static bool customDecrypt1(std::vector<uint8_t>& data);
    static bool customDecrypt2(std::vector<uint8_t>& data);
    static bool customDecrypt3(std::vector<uint8_t>& data);
    static bool customDecrypt4(std::vector<uint8_t>& data);
    static bool customDecrypt5(std::vector<uint8_t>& data);
    static bool customDecrypt6(std::vector<uint8_t>& data);
    static bool customDecrypt7(std::vector<uint8_t>& data);
    static bool customDecrypt8(std::vector<uint8_t>& data);
    static bool customDecrypt9(std::vector<uint8_t>& data);
    static bool customDecrypt10(std::vector<uint8_t>& data);
    static bool customDecrypt11(std::vector<uint8_t>& data);
    static bool customDecrypt12(std::vector<uint8_t>& data);
    static bool customDecrypt13(std::vector<uint8_t>& data);
    static bool customDecrypt14(std::vector<uint8_t>& data);
    static bool customDecrypt15(std::vector<uint8_t>& data);
    static bool customDecrypt16(std::vector<uint8_t>& data);
    static bool customDecrypt17(std::vector<uint8_t>& data);
    static bool customDecrypt18(std::vector<uint8_t>& data);
    static bool customDecrypt19(std::vector<uint8_t>& data);
    static bool customDecrypt20(std::vector<uint8_t>& data);

private:
    std::map<std::string, DecryptMethod> m_methods;
    
    bool validateDecryption(const std::vector<uint8_t>& data);
};

} // namespace metadata
