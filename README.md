# Metadata-Worker

**IL2CPP Metadata Tool - Compare, Extract, Decrypt, Dump APK**

A comprehensive Python tool for working with Unity IL2CPP global-metadata.dat files. Supports 20+ decryption methods and metadata versions 15-42 (Unity 2015-2025.x).

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
Dev Telegram: DanyaVoredom.t.me
---

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
python Metadata-Worker.py apk game.apk -o metadata.dat -f  # force
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
  0. Exit
============================================================
Select option: _
```

---

## Project Structure

```
game/
├── Metadata-Worker.py      # Main script
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
# Then use Frida on device
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
