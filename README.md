# SmaliForge

A desktop Python GUI for decompiling, rebuilding, and deploying Android APKs with ADB and Apktool.

## Features

* Detect connected Android devices and browse installed packages.
* Pull and decompile base or split APKs.
* Rebuild, validate, align, and sign modified APKs.
* Reuse validated builds with automatic clean fallback.
* Support persistent or session-only development signing keys.
* Optionally reinstall rebuilt APKs to the connected device.
* Detect update/signature conflicts before replacing an installed app.
* Show live progress, elapsed time, and build output.

## Requirements

* Python 3.11+
* Android Platform Tools (`adb`)
* Java/JDK
* Android SDK Build Tools (`zipalign`, `apksigner`)
* Tkinter
* Python `keyring`

Install dependencies:

```bash
pip install -r requirements.txt
```

Run:

```bash
python android_smali_gui.py
```

Apktool can be installed or updated directly from within SmaliForge.

## Usage

1. Connect an Android device with USB debugging enabled.
2. Select a package and decompile it.
3. Modify the decoded resources or smali.
4. Recompile the package.
5. Optionally install the rebuilt APK back to the device.

SmaliForge supports split APK sets and preserves configuration splits that should not be rebuilt independently.

## Signing and installation

SmaliForge can reuse a persistent development signing key across launches. The signing password is stored through the operating system credential store rather than in the application config.

Rebuilt apps usually do not share the signing certificate of the original Play Store version. If Android rejects an update because of a signature mismatch, SmaliForge will not automatically remove the installed app. It requires separate confirmation before performing a fresh install that may erase app data.

## Smart builds

SmaliForge validates generated DEX files and can reuse previously validated builds when the project has not changed.

Changed projects may use Apktool's incremental cache, with an automatic clean rebuild if the incremental build fails.

## Safety

Use SmaliForge only with devices and applications you own or are authorized to inspect or modify.

## Third-party tools

SmaliForge is not affiliated with Google, Android, or Apktool.

* Apktool is developed by iBotPeaches and contributors.
* Android Platform Tools and Android SDK Build Tools are provided by Google.

## License

MIT
