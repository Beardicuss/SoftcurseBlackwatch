# Softcurse Sentinel

![Softcurse Sentinel Banner](Softcurse.UI/Assets/logo%20with%20txt.png)

**Softcurse Sentinel** is a high-performance, visually stunning anti-cheat and system monitoring solution for Windows. Built with a "Cyberpunk-Industrial" aesthetic, it combines military-grade monitoring with a fluid, glassy user interface.

## ✨ Key Features

### 🖥️ Advanced Dashboard
- **Glassy UI Architecture:** Transparent cards with real-time blur and depth effects.
- **Micro-Animations:** Fluid progress bar interpolation and breathing background sigils for a stable, professional feel.
- **Dynamic Monitoring:** Real-time tracking of CPU usage, RAM utilization, and active system processes.

### 🛡️ Security & Detection
- **Scan Lifecycle:** Automated scanning routines with step-by-step status feedback (Enumeration → Analysis → Correlation).
- **Threat Mitigation:** Instant identification of suspicious activity with a one-click "PURGE" protocol.
- **Process & Network Visibility:** Deep insights into active connections and process behaviors.

### 🎨 Visual & UX Excellence
- **Neon Glow Aesthetics:** Cyber-cyan and magenta accents with intense neon glow borders.
- **Responsive Animations:** Hover-sensitive glow intensification and smooth value transitions.
- **Professional Polish:** Custom-designed status bar with containerized shield indicators and decorative tech accents.

## 🛠️ Tech Stack
- **UI Framework:** WPF (.NET 9)
- **Architecture:** MVVM (Model-View-ViewModel)
- **Monitoring:** WMI / System.Diagnostics / Native Windows APIs
- **Design System:** Custom XAML ResourceDictionaries with GPU-optimized effects.

## 🚀 Getting Started

### Prerequisites
- .NET 9.0 SDK
- Windows 10/11 (x64)

### Installation
1. Clone the repository:
   ```powershell
   git clone https://github.com/Beardicuss/SoftcurseSentinel.git
   ```
2. Navigate to the solution folder:
   ```powershell
   cd SoftcurseSentinel
   ```
3. Run the application:
   ```powershell
   dotnet run --project Softcurse.UI/Softcurse.UI.csproj
   ```

### Publishing the EXE
To generate a standalone, self-contained executable:
```powershell
dotnet publish Softcurse.UI/Softcurse.UI.csproj -c Release --self-contained -r win-x64 -o ./publish
```

## 📦 Deployment
The project includes a pre-configured **Inno Setup (.iss)** script for creating professional installers.
- **`SoftcurseSentinel.iss`**: Configured with custom branding and administrative privilege requirements.

---
Developed by **Beardicuss / Softcurse Inc.**
"Surgeon's hands, not DJ lights."
