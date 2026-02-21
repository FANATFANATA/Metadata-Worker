# Metadata-Worker

**[English](#english)** | **[Русский](#russian)**

---

<a id="english"></a>
# IL2CPP Metadata Tool

**IL2CPP Metadata Tool - Compare, Extract, Decrypt, Dump APK**

A comprehensive Python tool for working with Unity IL2CPP global-metadata.dat files. Supports 20+ decryption methods and metadata versions 15-42 (Unity 2015-2025.x).

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## Contacts

Telegram: @DanyaVoredom https://DanyaVoredom.t.me

## Features

### 🔓 Decryption Methods
- **WANZG Auto** - Automatic key detection (0x100 pattern)
- **AUTO-XOR** - Universal XOR key finder (3-12 bytes)
- **Striped XOR** - 0xA3 and 0x53 (Free Fire, Wild Rift, MLBB)
- **RC4** - wanzg, NEP2, Tarkov keys
- **XXTEA** - Block cipher support
- **Common XOR Keys** - Predefined key database

### 📊 Supported Metadata Versions
| Version | Unity | Version | Unity |
|---------|-------|---------|-------|
| 15-20 | 2015-2017 | 31 | 2022.2 |
| 21-23 | 2018 | 32 | 2023 |
| 24-26 | 2019-2020 | 33-34 | 2023.1-2023.2 |
| 27-29 | 2020.2-2021 | 35-38 | 2024.x |
| 30 | 2022 | 39-42 | 2025.x (experimental) |

### 🛠️ Commands
1. **Compare** - Compare two metadata files
2. **Frida** - Generate Frida interception script
3. **Extract** - Extract from libunity.so (embedded or via relocations)
4. **Decrypt** - Decrypt encrypted metadata with auto-detection
5. **Info** - Display metadata version and encryption status
6. **APK** - Extract from APK or unpacked folder
7. **Memory-Dump** - Generate Frida memory dump script (CameroonD style)
8. **Il2CppDumper** - Run Il2CppDumper.exe integration
9. **Menu** - Interactive TUI menu

---

## Installation

### Requirements
- Python 3.8+
- pip

### Install Dependencies
```bash
pip install tqdm colorama pyelftools
```

### Optional
- **Il2CppDumper.exe** - Place in the same folder for command #8
- **Frida** - `pip install frida frida-tools` (for memory dump)

---

## Usage

### Interactive Menu (Recommended)
```bash
python Metadata-Worker.py
```

### Command Line

#### Compare Metadata Files
```bash
python Metadata-Worker.py compare global-metadata.dat 2global-metadata.dat
python Metadata-Worker.py compare file1.dat file2.dat -b 20
```

#### Generate Frida Script
```bash
python Metadata-Worker.py frida 0x123456 -o script.js
```

#### Extract from libunity.so
```bash
python Metadata-Worker.py extract libunity.so -o extracted.dat
python Metadata-Worker.py extract libunity.so -o out.dat -s 50000000
```

#### Decrypt Metadata
```bash
python Metadata-Worker.py decrypt encrypted.dat -o decrypted.dat
```

#### Show Metadata Info
```bash
python Metadata-Worker.py info global-metadata.dat
```

#### Extract from APK/Folder
```bash
python Metadata-Worker.py apk game.apk -o metadata.dat
python Metadata-Worker.py apk unpacked_folder -o metadata.dat
python Metadata-Worker.py apk game.apk -o metadata.dat -f
```

#### Generate Frida Memory Dump Script
```bash
python Metadata-Worker.py memory-dump -o dump-metadata.js
```

**Usage (Android with root):**
```bash
python dump-metadata.py com.game.package
python dump-metadata.py com.game.package -o 0x123456
```

#### Run Il2CppDumper
```bash
python Metadata-Worker.py il2cppdumper libil2cpp.so global-metadata.dat -o output
```

---

## Decryption Examples

### Auto-Detection
```bash
python Metadata-Worker.py decrypt encrypted.dat -o decrypted.dat
```

Auto-detects and decrypts:
- ✅ WANZG (wan'zg key)
- ✅ XOR (3-12 bytes)
- ✅ Striped XOR (0xA3, 0x53)
- ✅ RC4 (wanzg, NEP2, Tarkov)
- ✅ XXTEA

### Manual XOR Key
If auto-detection fails, the tool tries common keys:
- `wan'zg` (0x77, 0x61, 0x6E, 0x7A, 0x67)
- `0xAA`, `0x5A`, `0x0A`, `0xFF`
- And more...

---

## Menu Interface

```
============================================================
  1. Compare metadata files
  2. Generate Frida script
  3. Extract metadata from libunity.so
  4. Decrypt metadata
  5. Show metadata info
  6. Extract from APK/folder
  7. Generate Frida memory dump script
  8. Run Il2CppDumper
  9. Switch Language / Сменить язык
  0. Exit
============================================================
Select option: _
```

---

## Project Structure

```
game/
├── Metadata-Worker.py      # Main script
├── i18n.py                 # Localization module
├── README.md               # This file
├── config.json             # Il2CppDumper config (optional)
├── Il2CppDumper.exe        # Il2CppDumper (optional)
├── dump-metadata.js        # Generated Frida script
└── dump-metadata.py        # Generated Python runner
```

---

## Troubleshooting

### "Il2CppDumper.exe not found"
Download from: https://github.com/Perfare/Il2CppDumper/releases
Place in the same folder as `Metadata-Worker.py`

### "Metadata version 39 unsupported"
Versions 39-42 are experimental. Try runtime dump instead:
```bash
python Metadata-Worker.py memory-dump
```

### "No metadata found in APK"
Try unpacked folder:
```bash
apktool d game.apk -o game_folder
python Metadata-Worker.py apk game_folder -o metadata.dat
```

### "Invalid magic bytes"
Metadata is encrypted. Use decrypt command:
```bash
python Metadata-Worker.py decrypt global-metadata.dat -o decrypted.dat
```

---

## Advanced: Frida Memory Dump

### Requirements
- Rooted Android device
- `pip install frida frida-tools`
- USB debugging enabled

### Usage
1. Generate script:
   ```bash
   python Metadata-Worker.py memory-dump
   ```

2. Push to device:
   ```bash
   adb push dump-metadata.js /data/local/tmp/
   adb push dump-metadata.py /data/local/tmp/
   ```

3. Run:
   ```bash
   adb shell
   cd /data/local/tmp
   python dump-metadata.py com.game.package
   ```

4. Pull result:
   ```bash
   adb pull /data/local/tmp/com.game.package_global-metadata.dat
   ```

---

## Credits

- **Il2CppDumper** - https://github.com/Perfare/Il2CppDumper
- **frida-il2cpp-bridge** - https://github.com/vfsfitvnm/frida-il2cpp-bridge
- **Il2CppMetadataExtractor** - https://github.com/CameroonD/Il2CppMetadataExtractor
- **Il2CppInspectorFix** - https://github.com/rotmg-network/Il2CppInspectorFix

---

## License

MIT License - Feel free to use and modify.

---

## Support

If you encounter issues:
1. Check the Troubleshooting section
2. Run with `--help` for command options
3. Use interactive menu for guided workflow

---

## Typical Workflow

```bash
# 1. Extract from APK
python Metadata-Worker.py apk game.apk -o metadata.dat

# 2. Check info
python Metadata-Worker.py info metadata.dat

# 3. Decrypt if needed
python Metadata-Worker.py decrypt metadata.dat -o decrypted.dat

# 4. Dump with Il2CppDumper
python Metadata-Worker.py il2cppdumper libil2cpp.so decrypted.dat -o output
```

Or just use the interactive menu:
```bash
python Metadata-Worker.py
```

---

<a id="russian"></a>
# IL2CPP Metadata Tool (Русский)

**Инструмент для работы с IL2CPP метаданными Unity**

Многофункциональный Python инструмент для работы с файлами global-metadata.dat из Unity IL2CPP. Поддерживает 20+ методов расшифровки и версии метаданных 15-42 (Unity 2015-2025.x).

## Контакты

Telegram: @DanyaVoredom https://DanyaVoredom.t.me

## Возможности

### 🔓 Методы расшифровки
- **WANZG Auto** - Автоматическое определение ключа (паттерн 0x100)
- **AUTO-XOR** - Универсальный поиск XOR ключа (3-12 байт)
- **Striped XOR** - 0xA3 и 0x53 (Free Fire, Wild Rift, MLBB)
- **RC4** - ключи wanzg, NEP2, Tarkov
- **XXTEA** - Поддержка блочного шифра
- **Common XOR Keys** - База предустановленных ключей

### 📊 Поддерживаемые версии метаданных
| Версия | Unity | Версия | Unity |
|--------|-------|--------|-------|
| 15-20 | 2015-2017 | 31 | 2022.2 |
| 21-23 | 2018 | 32 | 2023 |
| 24-26 | 2019-2020 | 33-34 | 2023.1-2023.2 |
| 27-29 | 2020.2-2021 | 35-38 | 2024.x |
| 30 | 2022 | 39-42 | 2025.x (экспериментально) |

### 🛠️ Команды
1. **Compare** - Сравнение двух файлов метаданных
2. **Frida** - Генерация скрипта перехвата Frida
3. **Extract** - Извлечение из libunity.so (встроенные или через релокации)
4. **Decrypt** - Расшифровка с авто-определением
5. **Info** - Показать версию и статус шифрования
6. **APK** - Извлечение из APK или распакованной папки
7. **Memory-Dump** - Скрипт дампа памяти Frida (стиль CameroonD)
8. **Il2CppDumper** - Запуск Il2CppDumper.exe
9. **Menu** - Интерактивное TUI меню

---

## Установка

### Требования
- Python 3.8+
- pip

### Установка зависимостей
```bash
pip install tqdm colorama pyelftools
```

### Опционально
- **Il2CppDumper.exe** - Для команды #8
- **Frida** - `pip install frida frida-tools` (для дампа памяти)

---

## Использование

### Интерактивное меню (Рекомендуется)
```bash
python Metadata-Worker.py
```

### Командная строка

#### Сравнение файлов метаданных
```bash
python Metadata-Worker.py compare global-metadata.dat 2global-metadata.dat
python Metadata-Worker.py compare file1.dat file2.dat -b 20
```

#### Генерация скрипта Frida
```bash
python Metadata-Worker.py frida 0x123456 -o script.js
```

#### Извлечение из libunity.so
```bash
python Metadata-Worker.py extract libunity.so -o extracted.dat
python Metadata-Worker.py extract libunity.so -o out.dat -s 50000000
```

#### Расшифровка метаданных
```bash
python Metadata-Worker.py decrypt encrypted.dat -o decrypted.dat
```

#### Информация о метаданных
```bash
python Metadata-Worker.py info global-metadata.dat
```

#### Извлечение из APK/папки
```bash
python Metadata-Worker.py apk game.apk -o metadata.dat
python Metadata-Worker.py apk unpacked_folder -o metadata.dat
python Metadata-Worker.py apk game.apk -o metadata.dat -f
```

#### Генерация скрипта дампа памяти
```bash
python Metadata-Worker.py memory-dump -o dump-metadata.js
```

**Использование (Android с root):**
```bash
python dump-metadata.py com.game.package
python dump-metadata.py com.game.package -o 0x123456
```

#### Запуск Il2CppDumper
```bash
python Metadata-Worker.py il2cppdumper libil2cpp.so global-metadata.dat -o output
```

---

## Примеры расшифровки

### Авто-определение
```bash
python Metadata-Worker.py decrypt encrypted.dat -o decrypted.dat
```

Авто-определяет и расшифровывает:
- ✅ WANZG (ключ wan'zg)
- ✅ XOR (3-12 байт)
- ✅ Striped XOR (0xA3, 0x53)
- ✅ RC4 (wanzg, NEP2, Tarkov)
- ✅ XXTEA

### Ручной XOR ключ
Если авто-определение не сработало, инструмент пробует стандартные ключи:
- `wan'zg` (0x77, 0x61, 0x6E, 0x7A, 0x67)
- `0xAA`, `0x5A`, `0x0A`, `0xFF`
- И другие...

---

## Интерфейс меню

```
============================================================
  1. Сравнить файлы метаданных
  2. Создать скрипт Frida
  3. Извлечь метаданные из libunity.so
  4. Расшифровать метаданные
  5. Показать информацию о метаданных
  6. Извлечь из APK/папки
  7. Создать скрипт дампа памяти Frida
  8. Запустить Il2CppDumper
  9. Switch Language / Сменить язык
  0. Выход
============================================================
Выберите опцию: _
```

---

## Структура проекта

```
game/
├── Metadata-Worker.py      # Основной скрипт
├── i18n.py                 # Модуль локализации
├── README.md               # Этот файл
├── config.json             # Конфиг Il2CppDumper (опционально)
├── Il2CppDumper.exe        # Il2CppDumper (опционально)
├── dump-metadata.js        # Сгенерированный скрипт Frida
└── dump-metadata.py        # Сгенерированный Python runner
```

---

## Решение проблем

### "Il2CppDumper.exe not found"
Скачать: https://github.com/Perfare/Il2CppDumper/releases
Поместить в ту же папку, что и `Metadata-Worker.py`

### "Metadata version 39 unsupported"
Версии 39-42 экспериментальные. Попробуйте дамп в рантайме:
```bash
python Metadata-Worker.py memory-dump
```

### "No metadata found in APK"
Попробуйте распакованную папку:
```bash
apktool d game.apk -o game_folder
python Metadata-Worker.py apk game_folder -o metadata.dat
```

### "Invalid magic bytes"
Метаданные зашифрованы. Используйте decrypt:
```bash
python Metadata-Worker.py decrypt global-metadata.dat -o decrypted.dat
```

---

## Продвинутое: Дамп памяти Frida

### Требования
- Rooted Android устройство
- `pip install frida frida-tools`
- Включена отладка по USB

### Использование
1. Генерация скрипта:
   ```bash
   python Metadata-Worker.py memory-dump
   ```

2. Отправка на устройство:
   ```bash
   adb push dump-metadata.js /data/local/tmp/
   adb push dump-metadata.py /data/local/tmp/
   ```

3. Запуск:
   ```bash
   adb shell
   cd /data/local/tmp
   python dump-metadata.py com.game.package
   ```

4. Получение результата:
   ```bash
   adb pull /data/local/tmp/com.game.package_global-metadata.dat
   ```

---

## Благодарности

- **Il2CppDumper** - https://github.com/Perfare/Il2CppDumper
- **frida-il2cpp-bridge** - https://github.com/vfsfitvnm/frida-il2cpp-bridge
- **Il2CppMetadataExtractor** - https://github.com/CameroonD/Il2CppMetadataExtractor
- **Il2CppInspectorFix** - https://github.com/rotmg-network/Il2CppInspectorFix

---

## Лицензия

MIT License - свободно используйте и модифицируйте.

---

## Поддержка

При возникновении проблем:
1. Проверьте раздел "Решение проблем"
2. Используйте `--help` для опций команд
3. Используйте интерактивное меню для пошаговой работы

---

## Типичный рабочий процесс

```bash
# 1. Извлечение из APK
python Metadata-Worker.py apk game.apk -o metadata.dat

# 2. Проверка информации
python Metadata-Worker.py info metadata.dat

# 3. Расшифровка при необходимости
python Metadata-Worker.py decrypt metadata.dat -o decrypted.dat

# 4. Дамп через Il2CppDumper
python Metadata-Worker.py il2cppdumper libil2cpp.so decrypted.dat -o output
```

Или просто используйте интерактивное меню:
```bash
python Metadata-Worker.py
```
