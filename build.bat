@echo off

chcp 65001 >nul

cd /d "%~dp0"

pip install -r r.txt

pyinstaller --onefile ^
    --name Metadata-Worker ^
    --icon=NONE ^
    --add-data "src\i18n.py;." ^
    --hidden-import tkinter ^
    --hidden-import elftools.elf.elffile ^
    --hidden-import requests ^
    src\Metadata-Worker.py

pause
