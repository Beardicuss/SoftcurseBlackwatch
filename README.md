# Softcurse Sentinel

![Softcurse Sentinel Banner](Softcurse.UI/Assets/logo%20with%20txt.png)

**Softcurse Sentinel** is a high-performance, visually stunning anti-cheat and system monitoring solution for Windows. Built with a "Cyberpunk-Industrial" aesthetic, it combines military-grade monitoring with a fluid, modern user interface powered by React and WebView2.

## ✨ Key Features

### 🖥️ Advanced Dashboard
- **Real-Time Monitoring:** Live CPU usage, RAM utilization, and active process tracking with animated charts.
- **Holographic Threat Sphere:** 3D hologram indicator that turns red when threats are detected.
- **Micro-Animations:** Fluid page transitions, breathing glows, and smooth stat interpolation.

### 🛡️ Security & Detection
- **Automated Scanning:** Background scan every 5 seconds with step-by-step status (Enumeration → Analysis → Network Correlation).
- **Instant Threat Scoring:** New processes are scored immediately via WMI watcher (closes the 5-second scan gap).
- **One-Click Purge:** Terminate all high-severity threats with a single command (with dry-run safety mode).
- **Process Whitelist:** Exclude trusted processes from threat scoring via manual entry or file browser.

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
| **Frontend** | React 18 + TypeScript + Vite |
| **UI Framework** | TailwindCSS + Framer Motion |
| **Desktop Shell** | WPF (.NET 9) + WebView2 |
| **Architecture** | MVVM (ViewModel) + JS Bridge |
| **Monitoring** | WMI / System.Diagnostics / PerformanceCounter |
| **Logging** | Buffered StreamWriter with auto-rotation |
| **Packaging** | Inno Setup (x64 installer) |

## 📁 Project Structure

```
SoftcurseSentinel/
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
- .NET 9.0 SDK
- Node.js 18+ (for frontend development)
- Windows 10/11 (x64)
- WebView2 Runtime (bundled with Windows 11, [download for Windows 10](https://developer.microsoft.com/en-us/microsoft-edge/webview2/))

### Development

1. **Clone the repository:**
   ```powershell
   git clone https://github.com/Beardicuss/SoftcurseSentinel.git
   cd SoftcurseSentinel
   ```

2. **Build the React frontend:**
   ```powershell
   cd Frontend
   npm install
   npx vite build
   ```

3. **Copy build output to WPF project:**
   ```powershell
   Copy-Item dist\* ..\Softcurse.UI\WebUI\ -Recurse -Force
   ```

4. **Run the application:**
   ```powershell
   cd ..
   dotnet run --project Softcurse.UI/Softcurse.UI.csproj
   ```

### Publishing

Generate a standalone, self-contained executable:
```powershell
dotnet publish Softcurse.UI/Softcurse.UI.csproj -c Release --self-contained -r win-x64 -o ./publish
```

## 📦 Installer

The project includes a pre-configured **Inno Setup (.iss)** script for creating a professional Windows installer.

- **`SoftcurseSentinel.iss`** — Configured with custom branding, admin privileges, and desktop shortcut.
- Compile with [Inno Setup 6+](https://jrsoftware.org/isinfo.php) to generate `SoftcurseSentinelSetup.exe`.

## 🔐 Architecture: C# ↔ React Bridge

Communication between the WPF backend and React frontend uses WebView2's message protocol:

| Direction | Method | Example |
|---|---|---|
| **C# → JS** | `ExecuteScriptAsync()` | `window.updateSentinelData(json)` |
| **JS → C#** | `postMessage()` | `chrome.webview.postMessage('scan')` |

Commands: `minimize`, `maximize`, `close`, `dragstart`, `scan`, `purge`, `purge_confirmed`, `navigate:N`, `kill:PID`, `setting:key:value`, `whitelist:add|remove|browse:value`

---
Developed by **Beardicuss / Softcurse Inc.**
