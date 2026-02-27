import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface Connection {
    state: string;
    localEndpoint: string;
    remoteEndpoint: string;
    remotePort: number;
    processName: string;
    suspiciousReason: string;
}

export function NetworkPage() {
    const [connections, setConnections] = useState<Connection[]>([]);
    const [count, setCount] = useState(0);
    const [suspiciousCount, setSuspiciousCount] = useState(0);

    useEffect(() => {
        (window as any).updateNetwork = (json: string) => {
            try {
                const data = JSON.parse(json);
                setConnections(data.items || []);
                setCount(data.count || 0);
                setSuspiciousCount(data.suspiciousCount || 0);
            } catch { }
        };
        return () => { delete (window as any).updateNetwork; };
    }, []);

    return (
        <div className="flex-1 flex flex-col p-5 overflow-hidden">
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
                <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.6"><circle cx="12" cy="12" r="10" /><ellipse cx="12" cy="12" rx="4" ry="10" /></svg>
                </div>
                <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">
                    NETWORK MONITOR
                </h2>
                <span className="text-xs text-[var(--text-dim)] font-['Share_Tech_Mono']">— {count} connections</span>
                {suspiciousCount > 0 && (
                    <span className="text-xs font-bold text-[#ff2244] font-['Share_Tech_Mono']">({suspiciousCount} suspicious)</span>
                )}
            </motion.div>

            <div className="flex-1 overflow-auto">
                <table className="w-full text-xs font-['Share_Tech_Mono']">
                    <thead>
                        <tr className="border-b border-[rgba(0,240,255,0.2)]">
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">STATUS</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PROCESS</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">LOCAL</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">REMOTE</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PORT</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">FLAG</th>
                        </tr>
                    </thead>
                    <tbody>
                        {connections.length === 0 ? (
                            <tr><td colSpan={6} className="py-8 text-center text-[var(--text-dim)]">Loading connections...</td></tr>
                        ) : connections.map((c, i) => (
                            <tr key={i} className="border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                                <td className="py-2 px-3 text-[var(--text-primary)]">{c.state}</td>
                                <td className="py-2 px-3 text-[var(--text-primary)]">{c.processName}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)]">{c.localEndpoint}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)]">{c.remoteEndpoint}</td>
                                <td className="py-2 px-3 text-[var(--text-primary)]">{c.remotePort}</td>
                                <td className="py-2 px-3 font-bold text-[#ff2244]">{c.suspiciousReason}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
