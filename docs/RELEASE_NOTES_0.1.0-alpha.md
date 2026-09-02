# Softcurse Blackwatch 0.1.0 Early Alpha

This is the first public home-user preview of Softcurse Blackwatch. It is an early alpha, not a finished antivirus product.

## What works

- Live CPU, memory, process, and TCP connection monitoring.
- Process identity enrichment with executable path, SHA-256, publisher, signature, parent, memory, and thread information.
- Explainable heuristic process scoring and process/network evidence correlation.
- Manual Scan Now workflow and guarded, confirmed high-severity process response.
- Dry-run mode enabled by default.
- Identity-bound trusted applications.
- Privacy-redacted local logs and diagnostic ZIP export.
- Per-user Windows installer and portable ZIP.
- Full in-app FAQ describing behavior, limitations, privacy, and safety.

## Important limitations

- Blackwatch is not a replacement for Microsoft Defender or another reputable antivirus.
- It does not provide malware signatures, kernel monitoring, on-access file scanning, packet interception, ransomware protection, or cloud reputation.
- A “no suspicious activity” result is not proof that the computer is clean.
- Detection quality and false-positive behavior still require broader real-world validation.
- The installer is intentionally unsigned and Windows SmartScreen may show an unknown-publisher warning.
- There is no Softcurse server, account, telemetry upload, or in-app updater.

## Installation

Download `SoftcurseBlackwatchSetup.exe` from this release. If Windows shows SmartScreen, verify that the downloaded file's SHA-256 matches `SHA256SUMS.txt` before choosing to run it. The default installation is per-user and does not require administrator privileges.

The portable `SoftcurseBlackwatch-0.1.0-alpha-win-x64.zip` contains the same self-contained Windows x64 application without the installer.

## Safety recommendation

Keep Microsoft Defender enabled. Leave Dry-Run Mode enabled while evaluating detections, and review every path, publisher, signal, and process identity before approving a response action.

Created by Softcurse.
