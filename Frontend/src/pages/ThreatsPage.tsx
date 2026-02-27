import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface Threat {
    level: string;
    score: number;
    processName: string;
    pid: number;
    path: string;
    action: string;
}

export function ThreatsPage() {
    const [threats, setThreats] = useState<Threat[]>([]);
    const [count, setCount] = useState(0);

    useEffect(() => {
        (window as any).updateThreats = (json: string) => {
            try {
                const data = JSON.parse(json);
                setThreats(data.items || []);
                setCount(data.count || 0);
            } catch { }
        };
        return () => { delete (window as any).updateThreats; };
    }, []);

    const levelColor = (level: string) => {
        switch (level?.toLowerCase()) {
            case 'critical': return '#ff2244';
            case 'high': return '#ff6600';
            case 'suspicious': return '#ffaa00';
            case 'low': return '#00f0ff';
            default: return '#4a6a8a';
        }
    };

    return (
        <div className="flex-1 flex flex-col p-5 overflow-hidden">
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
                <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="2"><path d="M12 2L2 7V14C2 21 7.8 26.4 14 28C20.2 26.4 26 21 26 14V7L12 2Z" /></svg>
                </div>
                <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">
                    ACTIVE THREATS
                </h2>
                <span className="text-xs text-[var(--text-dim)] font-['Share_Tech_Mono']">— {count} flagged</span>
            </motion.div>

            <div className="flex-1 overflow-auto">
                <table className="w-full text-xs font-['Share_Tech_Mono']">
                    <thead>
                        <tr className="border-b border-[rgba(0,240,255,0.2)]">
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">LEVEL</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">SCORE</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PROCESS</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PID</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">PATH</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">ACTION</th>
                        </tr>
                    </thead>
                    <tbody>
                        {threats.length === 0 ? (
                            <tr><td colSpan={6} className="py-8 text-center text-[var(--text-dim)]">No threats detected</td></tr>
                        ) : threats.map((t, i) => (
                            <tr key={i} className="border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                                <td className="py-2 px-3 font-bold" style={{ color: levelColor(t.level) }}>{t.level}</td>
                                <td className="py-2 px-3 text-[var(--text-primary)]">{t.score}</td>
                                <td className="py-2 px-3 text-[var(--text-primary)]">{t.processName}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)]">{t.pid}</td>
                                <td className="py-2 px-3 text-[var(--text-dim)] truncate max-w-[300px]">{t.path}</td>
                                <td className="py-2 px-3 font-bold text-[var(--magenta)]">{t.action}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
