# Softcurse Blackwatch

![Softcurse Blackwatch](Softcurse.UI/Assets/blackwatch-logo.png)

**Softcurse Blackwatch** is a local process and network monitoring application for Windows home users. It presents explainable heuristic evidence for review; it is not a replacement for Windows Defender or an enterprise endpoint-protection platform.

> **Release status: 0.1.0 Early Alpha / Home Preview.** This build is for evaluation and feedback. It is unsigned, incomplete, and should be used alongside Microsoft Defender—not as a replacement antivirus.

## ✨ Key Features

### 🖥️ Advanced Dashboard
- **Real-Time Monitoring:** Live CPU usage, RAM utilization, and active process tracking with animated charts.
- **Holographic Threat Sphere:** 3D hologram indicator that turns red when threats are detected.
- **Micro-Animations:** Fluid page transitions, breathing glows, and smooth stat interpolation.

### 🛡️ Security & Detection
- **Automated Scanning:** Background scan every 5 seconds with step-by-step status (Enumeration → Analysis → Network Correlation).
- **Event-Triggered Scanning:** New-process events request a guarded scan without racing the active scoring cycle.
- **Confirmed Purge:** Terminate high-severity threats only after native consent, target identity verification, and journaled authorization (with dry-run safety mode).
- **Trusted Applications:** Exact executable identities are bound to canonical path, SHA-256, and publisher certificate when available.

### 🌐 Network & Process Visibility
- **Network Monitor:** Real-time TCP connection tracking with suspicious activity flagging and process ownership.
- **Process Explorer:** Full process table with memory, threads, parent info, threat level, and kill controls.
- **System Logs:** Color-coded log viewer (Critical/Error/Warning/Threat/Info/Debug) with timestamps.

### ⚙️ Settings & Configuration
- **Dry-Run Mode:** Test purge actions without actually terminating processes.
- **Minimize to Tray:** Background monitoring with system tray icon and balloon notifications.
- **CPU Spike Detection:** Configurable threshold and duration for CPU spike alerts.

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 19 + TypeScript 5.9 + Vite 8 |
| **UI Framework** | TailwindCSS + Framer Motion |
| **Desktop Shell** | WPF (.NET 10 LTS) + WebView2 |
| **Architecture** | MVVM (ViewModel) + JS Bridge |
| **Monitoring** | WMI / System.Diagnostics / PerformanceCounter |
| **Logging** | Buffered StreamWriter with auto-rotation |
| **Packaging** | Inno Setup (x64 installer) |

## 📁 Project Structure

```
SoftcurseBlackwatch/
├── Softcurse.UI/           # WPF shell + WebView2 host
│   ├── MainWindow.xaml.cs  # WebView2 init, data push, command handling
│   ├── ViewModels/         # MVVM ViewModel (scanning, monitoring, settings)
│   ├── WebUI/              # Built React app (vite build output)
│   └── Assets/             # Icons, manifest
├── Softcurse.Core/         # Scanning, scoring, detection engines
├── Softcurse.Monitor/      # SystemMonitor, ProcessWatcher, NetworkMonitor
├── Softcurse.Cleaner/      # Process termination with dry-run support
├── Softcurse.Shared/       # Models, config, logging
└── Frontend/              # React frontend source
    └── src/
        ├── App.tsx         # Root layout + routing + AnimatePresence
        ├── components/     # TitleBar, Sidebar, StatusBar, HologramSphere
        └── pages/          # Dashboard, Threats, Processes, Network, Logs, Settings
```

## 🚀 Getting Started

### Prerequisites
- .NET 10.0.400 SDK (pinned by `global.json`)
- .NET 8 runtime for the pinned Microsoft SBOM build tool
- Node.js 24.18.0 LTS (pinned by `.nvmrc`)
- Windows 10/11 (x64)
- WebView2 Runtime (bundled with Windows 11, [download for Windows 10](https://developer.microsoft.com/en-us/microsoft-edge/webview2/))

### Development

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/Beardicuss/SoftcurseBlackwatch.git
   cd SoftcurseBlackwatch
   ```

2. **Restore and build:**
   ```powershell
   npm ci --prefix Frontend
   dotnet build SoftcurseBlackwatch.sln
   ```

3. **Run the application:**
   ```powershell
   dotnet run --project Softcurse.UI/Softcurse.UI.csproj
   ```

### Publishing

Generate tested v0.1.0 Early Alpha release artifacts, an SPDX SBOM, and checksums. Install Inno Setup 6.7.1 first, or pass `-SkipInstaller` to create only the portable archive:
```powershell
./build.ps1
```

CI also creates GitHub artifact attestations for non-pull-request builds. Public GitHub Release publication and Authenticode signing remain intentionally disabled until a production code-signing certificate is provisioned.

## 📦 Installer

The project includes a pre-configured **Inno Setup (.iss)** script for creating a professional Windows installer.

- **`SoftcurseBlackwatch.iss`** — Configured with custom branding, per-user least-privilege installation, and an optional desktop shortcut.
- Compile with [Inno Setup 6+](https://jrsoftware.org/isinfo.php) to generate `SoftcurseBlackwatchSetup.exe`.

## 🔐 Architecture: C# ↔ React Bridge

Communication between the WPF backend and React frontend uses WebView2's message protocol:

| Direction | Method | Example |
|---|---|---|
| **C# → JS** | `PostWebMessageAsJson()` | Versioned, typed snapshot envelopes |
| **JS → C#** | `postMessage()` | Versioned, typed command envelopes |

The bridge uses versioned structured messages. Web content may request `scan`, `purge`, process-kill, navigation, settings, whitelist, recovery, and window actions. Live response requests require an independent native confirmation and a short-lived, target-bound authorization before the cleaner mutates the system.

---
Developed by **Beardicuss / Softcurse Inc.**
