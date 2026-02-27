import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface Process {
    name: string;
    pid: number;
    memoryMB: number;
    threadCount: number;
    parentName: string;
    path: string;
    level: string;
}

function sendCmd(cmd: string) {
    try { (window as any).chrome?.webview?.postMessage(cmd); } catch { }
}

export function ProcessesPage() {
    const [processes, setProcesses] = useState<Process[]>([]);
    const [count, setCount] = useState(0);

    useEffect(() => {
        (window as any).updateProcesses = (json: string) => {
            try {
                const data = JSON.parse(json);
                setProcesses(data.items || []);
                setCount(data.count || 0);
            } catch { }
        };
        return () => { delete (window as any).updateProcesses; };
    }, []);

    return (
        <div className="flex-1 flex flex-col p-5 overflow-hidden">
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
                <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.5"><rect x="7" y="7" width="10" height="10" rx="1" /><rect x="9" y="9" width="6" height="6" rx="0.5" /></svg>
                </div>
                <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">
                    PROCESS EXPLORER
                </h2>
                <span className="text-xs text-[var(--text-dim)] font-['Share_Tech_Mono']">— {count} running</span>
            </motion.div>

            <div className="flex-1 overflow-auto">
                <table className="w-full text-xs font-['Share_Tech_Mono']">
                    <thead>
                        <tr className="border-b border-[rgba(0,240,255,0.2)]">
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">THREAT</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">NAME</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PID</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">MEM (MB)</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">THREADS</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PARENT</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PATH</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">ACTION</th>
                        </tr>
                    </thead>
                    <tbody>
                        {processes.length === 0 ? (
                            <tr><td colSpan={8} className="py-8 text-center text-[var(--text-dim)]">Loading processes...</td></tr>
                        ) : processes.map((p, i) => (
                            <tr key={i} className="border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                                <td className="py-2 px-3 font-bold" style={{ color: p.level === 'Safe' ? '#4a6a8a' : '#ff6600' }}>{p.level || 'Safe'}</td>
                                <td className="py-2 px-3 text-[var(--text-primary)]">{p.name}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)]">{p.pid}</td>
                                <td className="py-2 px-3 text-[var(--text-primary)]">{p.memoryMB.toFixed(1)}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)]">{p.threadCount}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)]">{p.parentName}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)] truncate max-w-[250px]">{p.path}</td>
                                <td className="py-2 px-3">
                                    <button onClick={() => sendCmd(`kill:${p.pid}`)}
                                        className="px-2 py-0.5 text-[10px] border border-[#ff2244] text-[#ff2244] hover:bg-[rgba(255,34,68,0.15)] transition-colors tracking-wider">
                                        KILL
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
