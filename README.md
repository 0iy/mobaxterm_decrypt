# mobaxterm decryptor

[![Author](https://img.shields.io/badge/author-0iy-red.svg "Author")](https://github.com/0iy "Author")
[![Visitors](https://visitor-badge.laobi.icu/badge?page_id=0iy.mobaxterm_decrypt "Visitors")](https://github.com/0iy/mobaxterm_decrypt "Visitors")
[![Stars](https://img.shields.io/github/stars/0iy/mobaxterm_decrypt.svg?style=flat "Stars")](https://github.com/0iy/mobaxterm_decrypt "Stars")
[![License](https://img.shields.io/github/license/0iy/mobaxterm_decrypt.svg "License")](https://github.com/0iy/mobaxterm_decrypt/blob/master/LICENSE)

steals your own credentials back from mobaxterm. because why not.

## install

```bash
git clone https://github.com/0iy/mobaxterm_decrypt.git
cd mobaxterm_decrypt
pip install pycryptodome
```

## usage

```bash
python mobaxterm_decrypt.py                  # show credentials
python mobaxterm_decrypt.py --ssh          # ssh format
python mobaxterm_decrypt.py --json         # json
python mobaxterm_decrypt.py --export       # csv
python mobaxterm_decrypt.py --ini <path>  # custom ini file
```

## how it works

mobaxterm encrypts credentials with dpapi + aes. this reads the session key from registry/ini, decrypts your master password, then extracts everything.

reads from:
- `%APPDATA%\MobaXterm\MobaXterm.ini`
- `HKCU\Software\Mobatek\MobaXterm`

## requirements

- windows
- python 3.6+
- pycryptodome

## license

mit

---

based on [h0ny/MobaXtermDecryptor](https://github.com/h0ny/MobaXtermDecryptor)
