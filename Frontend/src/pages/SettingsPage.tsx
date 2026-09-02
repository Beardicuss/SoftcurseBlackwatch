import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { sendBridgeCommand } from '../bridge';

interface SettingsData {
    dryRunMode: boolean;
    minimizeToTray: boolean;
    whitelistItems: string[];
    trustedApplications: TrustedApplication[];
    cpuSpikeThreshold: number;
    cpuSpikeDuration: number;
    recoveryActions: RecoveryAction[];
}

interface RecoveryAction {
    actionId: string;
    actionType: string;
    targetName: string;
    targetPath: string;
    quarantinePath: string;
    status: string;
    errorMessage: string;
}

interface TrustedApplication {
    trustId: string;
    name: string;
    canonicalPath: string;
    sha256: string;
    publisherThumbprint: string;
    productName: string;
    companyName: string;
}

export function SettingsPage() {
    const [settings, setSettings] = useState<SettingsData>({
        dryRunMode: false,
        minimizeToTray: false,
        whitelistItems: [],
        trustedApplications: [],
        cpuSpikeThreshold: 80,
        cpuSpikeDuration: 5,
        recoveryActions: [],
    });

    useEffect(() => {
        window.updateSettings = (json: string) => {
            try {
                const data = JSON.parse(json) as Partial<SettingsData>;
                setSettings(current => ({ ...current, ...data, recoveryActions: Array.isArray(data.recoveryActions) ? data.recoveryActions : [] }));
            } catch (error) { console.error('Invalid settings payload', error); }
        };
        return () => { delete window.updateSettings; };
    }, []);

    return (
        <div className="flex-1 flex flex-col p-5 overflow-hidden">
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
                <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.5"><circle cx="12" cy="12" r="3" /><path d="M12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" /></svg>
                </div>
                <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">
                    SETTINGS
                </h2>
            </motion.div>

            <div className="flex-1 overflow-auto space-y-4 pr-4">
                {settings.recoveryActions.length > 0 && (
                    <div className="tech-card p-5 border-[#ff6600]">
                        <h3 className="text-sm font-bold text-[#ff8844] font-['Share_Tech_Mono'] tracking-wider mb-1">RECOVERY REVIEW REQUIRED</h3>
                        <p className="text-[11px] text-[var(--text-dim)] mb-3">Interrupted mutations could not be proven automatically. Review paths carefully; every choice is appended to the audit journal.</p>
                        <div className="space-y-3">
                            {settings.recoveryActions.map(item => (
                                <div key={item.actionId} className="bg-[var(--bg-deep)] border border-[rgba(255,102,0,0.35)] p-3 font-['Share_Tech_Mono']">
                                    <div className="flex justify-between gap-3">
                                        <div>
                                            <div className="text-[#ff8844] text-xs">{item.actionType} · {item.targetName || 'Unknown target'}</div>
                                            <div className="text-[10px] text-[var(--text-dim)] mt-1 break-all">ID {item.actionId}</div>
                                            <div className="text-[10px] text-[var(--text-primary)] mt-1 break-all">Target: {item.targetPath || 'Unavailable'}</div>
                                            {item.quarantinePath && <div className="text-[10px] text-[var(--text-primary)] break-all">Quarantine: {item.quarantinePath}</div>}
                                            {item.errorMessage && <div className="text-[10px] text-[#ffaa66] mt-1">{item.errorMessage}</div>}
                                        </div>
                                        <div className="text-[10px] text-[#ff8844]">{item.status}</div>
                                    </div>
                                    <div className="flex gap-2 mt-3">
                                        {item.quarantinePath && (
                                            <button type="button" onClick={() => sendBridgeCommand({ type: 'recovery', action: 'restore', value: item.actionId })} className="px-2 py-1 text-[10px] border border-[var(--cyan)] text-[var(--cyan)]">VERIFY + RESTORE</button>
                                        )}
                                        <button type="button" onClick={() => sendBridgeCommand({ type: 'recovery', action: 'finalize', value: item.actionId })} className="px-2 py-1 text-[10px] border border-[#ffaa00] text-[#ffaa00]">MARK COMPLETED</button>
                                        <button type="button" onClick={() => sendBridgeCommand({ type: 'recovery', action: 'dismiss', value: item.actionId })} className="px-2 py-1 text-[10px] border border-[#ff5577] text-[#ff5577]">DISMISS</button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
                {/* Dry-Run */}
                <div className="tech-card p-5">
                    <div className="flex items-center justify-between">
                        <div>
                            <h3 className="text-sm font-bold text-[var(--cyan)] font-['Share_Tech_Mono'] tracking-wider">DRY-RUN MODE</h3>
                            <p className="text-[11px] text-[var(--text-dim)] mt-1">When enabled, Purge logs actions but doesn't terminate processes.</p>
                        </div>
                        <button
                            onClick={() => {
                                setSettings(s => ({ ...s, dryRunMode: !s.dryRunMode }));
                                sendBridgeCommand({ type: 'setting', action: 'dryrun', enabled: !settings.dryRunMode });
                            }}
                            className={`w-12 h-6 rounded-full border transition-all relative ${settings.dryRunMode
                                ? 'bg-[rgba(0,240,255,0.2)] border-[var(--cyan)]'
                                : 'bg-[rgba(255,255,255,0.05)] border-[rgba(255,255,255,0.15)]'
                                }`}>
                            <div className={`w-4 h-4 rounded-full absolute top-0.5 transition-all ${settings.dryRunMode
                                ? 'left-6 bg-[var(--cyan)] shadow-[0_0_8px_var(--cyan)]'
                                : 'left-1 bg-[var(--text-dim)]'
                                }`} />
                        </button>
                    </div>
                </div>

                {/* Minimize to Tray */}
                <div className="tech-card p-5">
                    <div className="flex items-center justify-between">
                        <div>
                            <h3 className="text-sm font-bold text-[var(--cyan)] font-['Share_Tech_Mono'] tracking-wider">MINIMIZE TO TRAY</h3>
                            <p className="text-[11px] text-[var(--text-dim)] mt-1">Closing the window minimizes to system tray instead of exiting.</p>
                        </div>
                        <button
                            onClick={() => {
                                setSettings(s => ({ ...s, minimizeToTray: !s.minimizeToTray }));
                                sendBridgeCommand({ type: 'setting', action: 'tray', enabled: !settings.minimizeToTray });
                            }}
                            className={`w-12 h-6 rounded-full border transition-all relative ${settings.minimizeToTray
                                ? 'bg-[rgba(0,240,255,0.2)] border-[var(--cyan)]'
                                : 'bg-[rgba(255,255,255,0.05)] border-[rgba(255,255,255,0.15)]'
                                }`}>
                            <div className={`w-4 h-4 rounded-full absolute top-0.5 transition-all ${settings.minimizeToTray
                                ? 'left-6 bg-[var(--cyan)] shadow-[0_0_8px_var(--cyan)]'
                                : 'left-1 bg-[var(--text-dim)]'
                                }`} />
                        </button>
                    </div>
                </div>

                {/* Trusted applications */}
                <div className="tech-card p-5">
                    <div className="flex items-start justify-between gap-4 mb-3">
                        <div>
                            <h3 className="text-sm font-bold text-[var(--cyan)] font-['Share_Tech_Mono'] tracking-wider mb-1">TRUSTED APPLICATIONS</h3>
                            <p className="text-[11px] text-[var(--text-dim)]">Exceptions require the selected executable's canonical path and SHA-256. Signed files are also bound to their publisher certificate.</p>
                        </div>
                        <button onClick={() => sendBridgeCommand({ type: 'trusted', action: 'browse' })}
                            className="px-3 py-1.5 text-[10px] border border-[var(--cyan)] text-[var(--cyan)] hover:bg-[rgba(0,240,255,0.1)] transition-colors tracking-wider font-['Share_Tech_Mono'] whitespace-nowrap">
                            + TRUST FILE
                        </button>
                    </div>

                    <div className="space-y-2">
                        {settings.trustedApplications.length === 0 ? (
                            <p className="text-[11px] text-[var(--text-dim)]">No identity-bound trusted applications.</p>
                        ) : settings.trustedApplications.map(item => (
                            <div key={item.trustId} className="flex items-start justify-between gap-3 bg-[var(--bg-deep)] border border-[rgba(0,240,255,0.1)] px-3 py-2">
                                <div className="min-w-0 font-['Share_Tech_Mono']">
                                    <div className="text-xs text-[var(--text-primary)]">{item.productName || item.name}</div>
                                    <div className="text-[10px] text-[var(--text-dim)] break-all">{item.canonicalPath}</div>
                                    <div className="text-[10px] text-[var(--cyan)]">
                                        SHA-256 {item.sha256.slice(0, 20)}… · {item.publisherThumbprint ? 'SIGNED ' + (item.companyName || 'publisher verified') : 'UNSIGNED'}
                                    </div>
                                </div>
                                <button onClick={() => sendBridgeCommand({ type: 'trusted', action: 'remove', value: item.trustId })}
                                    className="text-[#ff2244] text-xs hover:text-[#ff4466] transition-colors">✕</button>
                            </div>
                        ))}
                    </div>

                    {settings.whitelistItems.length > 0 && (
                        <div className="mt-4 border-t border-[rgba(255,170,0,0.25)] pt-3">
                            <div className="text-[10px] text-[#ffaa00] mb-2">LEGACY NAME ENTRIES — INACTIVE, REMOVE AFTER REVIEW</div>
                            <div className="space-y-1">
                                {settings.whitelistItems.map((item, i) => (
                                    <div key={i} className="flex items-center justify-between bg-[var(--bg-deep)] border border-[rgba(255,170,0,0.15)] px-3 py-1.5">
                                        <span className="text-xs text-[var(--text-dim)] font-['Share_Tech_Mono']">{item}</span>
                                        <button onClick={() => sendBridgeCommand({ type: 'whitelist', action: 'remove', value: item })}
                                            className="text-[#ff2244] text-xs hover:text-[#ff4466] transition-colors">✕</button>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                {/* Scan Config */}
                <div className="tech-card p-5 flex items-center justify-between gap-4">
                    <div>
                        <h3 className="text-sm font-bold text-[var(--cyan)] font-['Share_Tech_Mono'] tracking-wider mb-1">SUPPORT DIAGNOSTICS</h3>
                        <p className="text-[11px] text-[var(--text-dim)]">Export a local ZIP containing health metadata and retained logs. User paths, URL queries, and common secret fields are redacted again during export.</p>
                    </div>
                    <button type="button" onClick={() => sendBridgeCommand({ type: 'diagnostics', action: 'export' })}
                        className="px-3 py-1.5 text-[10px] border border-[var(--cyan)] text-[var(--cyan)] hover:bg-[rgba(0,240,255,0.1)] transition-colors tracking-wider font-['Share_Tech_Mono'] whitespace-nowrap">
                        EXPORT REDACTED ZIP
                    </button>
                </div>

                {/* Scan Config */}
                <div className="tech-card p-5">
                    <h3 className="text-sm font-bold text-[var(--cyan)] font-['Share_Tech_Mono'] tracking-wider mb-3">SCAN CONFIGURATION</h3>
                    <div className="space-y-2 text-xs font-['Share_Tech_Mono']">
                        <div className="flex gap-4">
                            <span className="text-[var(--text-dim)] w-[180px]">CPU Spike Threshold:</span>
                            <span className="text-[var(--cyan)]">{settings.cpuSpikeThreshold}%</span>
                        </div>
                        <div className="flex gap-4">
                            <span className="text-[var(--text-dim)] w-[180px]">Spike Duration:</span>
                            <span className="text-[var(--cyan)]">{settings.cpuSpikeDuration}s</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
