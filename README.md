# Android Smali GUI

A desktop Python GUI for inspecting Android applications on devices. It combines ADB, Apktool, Android SDK build tools, and a guarded rebuild/install workflow, all in one interface.

## Features

- Detect connected ADB devices and distinguish device/unauthorized states.
- Browse and filter user or system packages.
- Pull base and split APKs from a non-rooted Android device.
- Decode APKs to smali using Apktool.
- Rebuild single or split-package Apktool projects.
- Preserve configuration splits that should not be rebuilt independently.
- Validate generated DEX headers, SHA-1 signatures, Adler-32 checksums, and SHA-256 content hashes.
- Reuse validated unchanged builds and use trusted incremental Apktool builds with automatic clean fallback.
- Handle deep decoded package trees with Windows extended-length paths.
- Zipalign and sign rebuilt APK sets, then verify that every APK uses the same certificate.
- Optionally reuse one persistent development signing key across recompiles and launches. The password is stored through the operating system credential store via `keyring`.
- Optionally install rebuilt APKs back to the selected device.
- Detect an already-installed package and ask before attempting an in-place update.
- If Android rejects an update because signing certificates differ, require a separate confirmation before uninstalling the existing app and performing a fresh install.
- Determinate progress reporting plus a heartbeat/elapsed-time indicator while long commands run.

## Requirements

- Python 3.11+ recommended
- Tkinter
- Android Platform Tools (`adb`)
- Java/JDK (`java` and `keytool`)
- Apktool
- Android SDK Build Tools (`zipalign` and `apksigner`) for signing
- Python `keyring` package

Install the Python dependency:

```bash
pip install -r requirements.txt
```

Then run:

```bash
python android_smali_gui.py
```

The GUI can locate ADB from common Android SDK locations, or you can browse to it manually. Apktool can be downloaded from the official Apktool GitHub release feed from inside the application.

## Typical workflow

1. Enable USB debugging on an Android device and connect it over ADB.
2. Select the device and load installed apps.
3. Select one or more packages and choose **Decompile selected**.
4. Edit the decoded resources/smali in the output folder.
5. Choose **Recompile selected** or **Recompile folder…**.
6. The rebuilt APKs are validated, aligned, and signed.
7. If **Install to device after rebuild** is enabled, the GUI offers to install the resulting APK set.

## Output structure

A pulled package generally looks like:

```text
com.example.app/
├── apks/
│   ├── base.apk
│   └── split_config.arm64_v8a.apk
├── decoded/
│   ├── base/
│   └── split_config.arm64_v8a/
├── rebuilt/
│   ├── unsigned/
│   └── signed/
├── build_state/
└── pull_manifest.json
```

`pull_manifest.json` preserves the relationship between device APK paths, local APK filenames, and decoded project directories.

## Signing behavior

With **Reuse persistent signing key** enabled, Android Smali GUI reuses the same locally generated development keystore across launches. Its password is kept in the OS credential store through Python `keyring`.

With the option disabled, one session key is generated and reused only for recompiles during the current application process.

A development key will generally not match the certificate used by the original Play Store/app-store build. Android therefore may refuse an in-place update. The GUI first attempts the data-preserving update only after confirmation. If Android reports a certificate/signature conflict, the GUI separately offers to uninstall the existing package and install the rebuilt copy, with an explicit data-loss warning.

## Smart rebuilds

The build cache records a fingerprint of meaningful decoded inputs and hashes of validated output DEX files. If the project is unchanged and the previous APK still validates, the existing build can be reused. Changed projects may use Apktool's incremental cache only when a validated baseline exists; a failed incremental build automatically retries from a clean cache.

The application deliberately does **not** move arbitrary classes between DEX files to work around reference limits. DEX-layout changes can alter application behavior and should be handled explicitly by the developer.

## Safety and authorization

Use this application only with devices and applications you own or have permission to inspect or modify. Installing a rebuilt application can change or remove application data, especially when a signing conflict requires uninstalling the original package.

## Third-party tools

Android Smali GUI is not affiliated with Google, Android, or Apktool.

- Apktool is developed by iBotPeaches and contributors.
- Android Platform Tools and Android SDK Build Tools are provided by Google.

Those tools retain their own licenses; the MIT license in this repository applies to Android Smali GUI itself.

## License

MIT
