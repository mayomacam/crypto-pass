# Building BitMarrow Standalone (v5.0.0)

This guide explains how to package **BitMarrow** into a standalone executable. We use `PyInstaller` to bundle the Python interpreter, dependencies, and resources into a single file.

## 📋 Prerequisites

Ensure you have all dependencies installed from the updated `requirements.txt`:
```bash
pip install -r requirements.txt
pip install pyinstaller
```

## 🛠️ Build Steps (Windows)

To create a single portable `.exe` file with all necessary modules:

```bash
pyinstaller --noconsole --onefile --add-data "gui;gui" --add-data "core;core" --add-data "database;database" --add-data "generators;generators" --add-data "utils;utils" --add-data "config.py;." --name "BitMarrow" main.py
```

### Argument Breakdown:
- `--noconsole`: Prevents a terminal window from flashing in the background.
- `--onefile`: Bundles everything into a single `.exe`.
- `--add-data`: Includes the internal modules and configuration.
- `--name`: Sets the final filename.

The final executable will be located in the `dist/` folder.

## 🐧 Build Steps (Linux)

Similar to Windows, but using the colon `:` separator for data paths:

```bash
pyinstaller --noconsole --onefile --add-data "gui:gui" --add-data "core:core" --add-data "database:database" --add-data "generators:generators" --add-data "utils:utils" --add-data "config.py:." --name "BitMarrow" main.py
```

## ⚠️ Important Notes

1. **Anti-Virus:** Unsigned executables may trigger Windows Defender. This is normal for Python-based bundles. Users may need to click "Run anyway".
2. **Data Directory:** BitMarrow stores its database in a `data/` folder relative to the executable. Ensure the application has write permissions in its current directory.
3. **Icons:** To add an icon, use `--icon="assets/logo.ico"` (if available).
