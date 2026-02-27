import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface SettingsData {
    dryRunMode: boolean;
    minimizeToTray: boolean;
    whitelistItems: string[];
    cpuSpikeThreshold: number;
    cpuSpikeDuration: number;
}

function sendCmd(cmd: string) {
    try { (window as any).chrome?.webview?.postMessage(cmd); } catch { }
}

export function SettingsPage() {
    const [settings, setSettings] = useState<SettingsData>({
        dryRunMode: false,
        minimizeToTray: false,
        whitelistItems: [],
        cpuSpikeThreshold: 80,
        cpuSpikeDuration: 5,
    });
    const [whitelistInput, setWhitelistInput] = useState('');

    useEffect(() => {
        (window as any).updateSettings = (json: string) => {
            try {
                setSettings(JSON.parse(json));
            } catch { }
        };
        return () => { delete (window as any).updateSettings; };
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
                                sendCmd(`setting:dryrun:${!settings.dryRunMode}`);
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
                                sendCmd(`setting:tray:${!settings.minimizeToTray}`);
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

                {/* Whitelist */}
                <div className="tech-card p-5">
                    <h3 className="text-sm font-bold text-[var(--cyan)] font-['Share_Tech_Mono'] tracking-wider mb-1">PROCESS WHITELIST</h3>
                    <p className="text-[11px] text-[var(--text-dim)] mb-3">Processes matching these names or paths will be excluded from threat scoring.</p>

                    <div className="flex gap-2 mb-3">
                        <input
                            value={whitelistInput}
                            onChange={(e) => setWhitelistInput(e.target.value)}
                            placeholder="Enter process name or path..."
                            className="flex-1 bg-[var(--bg-deep)] border border-[rgba(0,240,255,0.15)] text-[var(--text-primary)] px-3 py-1.5 text-xs font-['Share_Tech_Mono'] focus:outline-none focus:border-[var(--cyan)]"
                        />
                        <button
                            onClick={() => { if (whitelistInput.trim()) { sendCmd(`whitelist:add:${whitelistInput.trim()}`); setWhitelistInput(''); } }}
                            className="px-3 py-1.5 text-[10px] border border-[var(--cyan)] text-[var(--cyan)] hover:bg-[rgba(0,240,255,0.1)] transition-colors tracking-wider font-['Share_Tech_Mono']">
                            + ADD
                        </button>
                        <button
                            onClick={() => sendCmd('whitelist:browse')}
                            className="px-3 py-1.5 text-[10px] border border-[var(--cyan)] text-[var(--cyan)] hover:bg-[rgba(0,240,255,0.1)] transition-colors tracking-wider font-['Share_Tech_Mono']">
                            📂 BROWSE
                        </button>
                    </div>

                    <div className="space-y-1">
                        {settings.whitelistItems.length === 0 ? (
                            <p className="text-[11px] text-[var(--text-dim)]">No items in whitelist</p>
                        ) : settings.whitelistItems.map((item, i) => (
                            <div key={i} className="flex items-center justify-between bg-[var(--bg-deep)] border border-[rgba(0,240,255,0.1)] px-3 py-1.5">
                                <span className="text-xs text-[var(--text-primary)] font-['Share_Tech_Mono']">{item}</span>
                                <button onClick={() => sendCmd(`whitelist:remove:${item}`)}
                                    className="text-[#ff2244] text-xs hover:text-[#ff4466] transition-colors">✕</button>
                            </div>
                        ))}
                    </div>
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
