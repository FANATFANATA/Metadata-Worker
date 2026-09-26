# Metadata-Worker

**[english](#english)** | **[русский](#russian)**

<a id="english"></a>

## english

a python tool for working with Unity IL2CPP global-metadata.dat.

telegram - [@DanyaVoredom](https://t.me/DanyaVoredom)

thanks to [Michel-M](https://github.com/Michel-M-code) for his [Metadata-Decryptor](https://github.com/Michel-M-code/Metadata-Decryptor)

### run

```
git clone https://github.com/FANATFANATA/Metadata-Worker
```

and:

```
python main.py
```

### commands

```
python main.py menu
python main.py extract <libunity.so> [output.dat]
python main.py decrypt <metadata.dat> [output.dat]
python main.py info <metadata.dat>
```

`menu` is the default when no command is given and walks through extraction and decryption interactively.

`extract` pulls the metadata blob out of a Unity binary. it locates the blob through the pointer relocations in the `data` section and falls back to a byte signature scan when needed.

`decrypt` rebuilds a valid metadata header for an already dumped blob. it detects the cipher, unshuffles the section table and writes a file that IL2CPP tools can read. use `--no-decrypt` to skip the cipher step and `--no-dump` to skip writing the raw probe next to the result.

```
python main.py decrypt metadata.dat output.dat --no-decrypt --no-dump
```

`info` prints the magic, the version and the size of a metadata file.

requirements:

```
pip install -r requirements.txt
```

tests:

```
python tests.py
```

<a id="russian"></a>

## русский

пайтон тула для работы с global-metadata.dat из Unity IL2CPP.

telegram: [@DanyaVoredom](https://t.me/DanyaVoredom)

спасибо [Michel-M](https://github.com/Michel-M-code) за его [Metadata-Decryptor](https://github.com/Michel-M-code/Metadata-Decryptor)

### запуск

```
git clone https://github.com/FANATFANATA/Metadata-Worker
```

потом:

```
python main.py
```

### команды

```
python main.py menu
python main.py extract <libunity.so> [output.dat]
python main.py decrypt <metadata.dat> [output.dat]
python main.py info <metadata.dat>
```

`menu` используется по умолчанию, если команда не указана, и проводит через извлечение и расшифровку в интерактивном режиме.

`extract` достаёт метаданные из Unity-бинарника. поиск идёт через релокации-указатели в секции `data`, а при необходимости включается сканирование по сигнатуре.

`decrypt` собирает корректный заголовок метаданных для уже снятого дампа. определяет шифр, разбирает таблицу секций и пишет файл, который читают инструменты IL2CPP. флаг `--no-decrypt` пропускает этап расшифровки, `--no-dump` не сохраняет сырой probe рядом с результатом.

```
python main.py decrypt metadata.dat output.dat --no-decrypt --no-dump
```

`info` показывает magic, версию и размер файла метаданных.

зависимости:

```
pip install -r requirements.txt
```

тесты:

```
python tests.py
```
