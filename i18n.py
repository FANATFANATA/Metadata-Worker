BANNER = """
 █     █░    ▒█████      ██▀███      ██ ▄█▀   ▓█████     ██▀███
▓█░ █ ░█░   ▒██▒  ██▒   ▓██ ▒ ██▒    ██▄█▒    ▓█   ▀    ▓██ ▒ ██▒
▒█░ █ ░█    ▒██░  ██▒   ▓██ ░▄█ ▒   ▓███▄░    ▒███      ▓██ ░▄█ ▒
░█░ █ ░█    ▒██   ██░   ▒██▀▀█▄     ▓██ █▄    ▒▓█  ▄    ▒██▀▀█▄
░░██▒██▓    ░ ████▓▒░   ░██▓ ▒██▒   ▒██▒ █▄   ░▒████▒   ░██▓ ▒██▒
░ ▓░▒ ▒     ░ ▒░▒░▒░    ░ ▒▓ ░▒▓░   ▒ ▒▒ ▓▒   ░░ ▒░ ░   ░ ▒▓ ░▒▓░
  ▒ ░ ░       ░ ▒ ▒░      ░▒ ░ ▒░   ░ ░▒ ▒░    ░ ░  ░     ░▒ ░ ▒░
  ░   ░     ░ ░ ░ ▒       ░░   ░    ░ ░░ ░       ░        ░░   ░
    ░           ░ ░        ░        ░  ░         ░  ░      ░
"""

LANGUAGES = {
    "en": {
        "path_to_file": "Path to file (or 'q' to cancel): ",
        "path_to_save": "Path to save (or 'q' to cancel): ",
        "path_to_folder": "Path to folder (or 'q' to cancel): ",
        "file_not_found": "File not found, try again",
        "enter_path": "Enter path",
        "folder_not_found": "Folder not found, try again",
        "select_libunity": "Select libunity.so",
        "select_encrypted": "Select encrypted metadata",
        "select_metadata": "Select metadata file",
        "save_metadata": "Save metadata",
        "save_decrypted": "Save decrypted metadata",
        "max_size": "Max size (30000000): ",
        "input": "Input: ",
        "file": "File: ",
        "libunity": "libunity.so: ",
        "no_file_selected": "Error: No file selected",
        "no_output_path": "Error: No output path selected",
        "invalid_option": "Invalid option",
        "exiting": "Exiting...",
        "press_enter": "Press Enter to continue...",
        "select_option": "Select option",
        "menu_extract": "Extract metadata from libunity.so",
        "menu_decrypt": "Decrypt metadata",
        "menu_info": "Show metadata info",
        "menu_switch_lang": "Switch Language / Сменить язык",
        "menu_exit": "Exit",
        "extract_title": "Extract Metadata from libunity.so",
        "decrypt_title": "Decrypt Metadata",
        "info_title": "Metadata Info",
        "error": "Error: ",
        "metadata_info_title": "Metadata Info",
        "magic": "Magic: ",
        "version": "Version: ",
        "file_size": "File size: ",
        "warning_invalid_magic": "Warning: Invalid magic bytes - file may be encrypted",
        "possible_encryption": "Possible encryption key: ",
        "extracted_to": "Metadata extracted to ",
        "exclude_offsets_prompt": "Exclude offsets (e.g., 1,2,3 or empty): ",
        "skip_decrypt_prompt": "Skip auto-decryption? (y/N): ",
        "approx_offset_added": "Offset added with approximate size",
        "heuristics_insufficient": "Heuristics only found",
        "trying_unshuffle": "sections, trying unshuffle...",
        "unshuffle_success": "Unshuffle succeeded.",
        "unshuffle_failed": "Unshuffle also failed.",
        "dep_missing": "Missing dependency: {package}",
        "dep_install_prompt": "Install {package}? (y/N): ",
        "dep_installing": "Installing {package}...",
        "dep_failed": "Failed to install {package}: {error}",
        "dep_cancelled": "Dependency not installed. Exiting.",
        "lang_changed": "Language changed to ",
        "validated_pairs": "Validated ",
        "offset_size_pairs": " offset-size pairs",
        "decrypt_success": "Decryption successful",
        "output": "Output",
        "warning_sections": "Warning: Found ",
        "expected_sections": " out of 29 expected sections",
    },
    "ru": {
        "path_to_file": "Путь к файлу (или 'q' для отмены): ",
        "path_to_save": "Путь для сохранения (или 'q' для отмены): ",
        "path_to_folder": "Путь к папке (или 'q' для отмены): ",
        "file_not_found": "Файл не найден, попробуйте снова",
        "enter_path": "Введите путь",
        "folder_not_found": "Папка не найдена, попробуйте снова",
        "select_libunity": "Выберите libunity.so",
        "select_encrypted": "Выберите зашифрованные метаданные",
        "select_metadata": "Выберите файл метаданных",
        "save_metadata": "Сохранить метаданные",
        "save_decrypted": "Сохранить расшифрованные метаданные",
        "max_size": "Макс размер (30000000): ",
        "input": "Вход: ",
        "file": "Файл: ",
        "libunity": "libunity.so: ",
        "no_file_selected": "Ошибка: Файл не выбран",
        "no_output_path": "Ошибка: Путь вывода не выбран",
        "invalid_option": "Неверная опция",
        "exiting": "Выход...",
        "press_enter": "Нажмите Enter для продолжения...",
        "select_option": "Выберите опцию",
        "menu_extract": "Извлечь метаданные из libunity.so",
        "menu_decrypt": "Расшифровать метаданные",
        "menu_info": "Показать информацию о метаданных",
        "menu_switch_lang": "Сменить язык / Switch Language",
        "menu_exit": "Выход",
        "extract_title": "Извлечение метаданных из libunity.so",
        "decrypt_title": "Расшифровка метаданных",
        "info_title": "Информация о метаданных",
        "error": "Ошибка: ",
        "metadata_info_title": "Информация о метаданных",
        "magic": "Magic: ",
        "version": "Версия: ",
        "file_size": "Размер файла: ",
        "warning_invalid_magic": "Внимание: Неверные magic bytes - файл может быть зашифрован",
        "possible_encryption": "Возможный ключ шифрования: ",
        "extracted_to": "Метаданные извлечены в ",
        "exclude_offsets_prompt": "Исключить смещения (например, 1,2,3 или пусто): ",
        "skip_decrypt_prompt": "Пропустить авто-расшифровку? (y/N): ",
        "approx_offset_added": "Добавлено смещение с примерным размером",
        "heuristics_insufficient": "Эвристики нашли только",
        "trying_unshuffle": "секций, пробуем unshuffle...",
        "unshuffle_success": "Unshuffle успешен.",
        "unshuffle_failed": "Unshuffle также не удался.",
        "dep_missing": "Отсутствует зависимость: {package}",
        "dep_install_prompt": "Установить {package}? (y/N): ",
        "dep_installing": "Установка {package}...",
        "dep_failed": "Не удалось установить {package}: {error}",
        "dep_cancelled": "Зависимость не установлена. Выход.",
        "lang_changed": "Язык изменён на ",
        "validated_pairs": "Проверено ",
        "offset_size_pairs": " пар смещение-размер",
        "decrypt_success": "Расшифровка успешна",
        "output": "Вывод",
        "warning_sections": "Внимание: Найдено ",
        "expected_sections": " из 29 ожидаемых секций",
    },
}
current_language = "en"


def get(key: str) -> str:
    return LANGUAGES[current_language].get(key, key)


def set_language(lang: str):
    global current_language
    if lang in LANGUAGES:
        current_language = lang


def toggle_language() -> str:
    global current_language
    current_language = "ru" if current_language == "en" else "en"
    return current_language
