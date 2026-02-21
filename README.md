# Metadata-Worker

IL2CPP Metadata Tool для работы с global-metadata.dat

## Возможности
- Извлечение из libunity.so / APK
- Расшифровка (XOR, RC4, XXTEA, Striped XOR)
- Генерация Frida скриптов
- Интеграция с Il2CppDumper

## Использование
```bash
python Metadata-Worker.py          # Интерактивное меню
python Metadata-Worker.py apk game.apk -o metadata.dat
python Metadata-Worker.py decrypt encrypted.dat -o decrypted.dat
```

## Контакты
Telegram: @DanyaVoredom
