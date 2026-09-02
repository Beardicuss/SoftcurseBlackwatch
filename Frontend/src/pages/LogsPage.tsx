import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface LogEntry {
    timestamp: string;
    level: string;
    source: string;
    message: string;
}

export function LogsPage() {
    const pageSize = 100;
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [page, setPage] = useState(0);

    useEffect(() => {
        window.updateLogs = (json: string) => {
            try {
                const data = JSON.parse(json);
                setLogs(data.items || []);
            } catch (error) { console.error('Invalid logs payload', error); }
        };
        return () => { delete window.updateLogs; };
    }, []);

    const pageCount = Math.max(1, Math.ceil(logs.length / pageSize));
    const safePage = Math.min(page, pageCount - 1);
    const visibleLogs = logs.slice(safePage * pageSize, (safePage + 1) * pageSize);

    const levelColor = (level: string) => {
        switch (level?.toLowerCase()) {
            case 'critical': return '#ff2244';
            case 'error': return '#ff2244';
            case 'threat': return '#ff6600';
            case 'warning': return '#ffaa00';
            case 'info': return '#00f0ff';
            case 'debug': return '#3a5a7a';
            default: return '#4a6a8a';
        }
    };

    return (
        <div className="flex-1 flex flex-col p-5 overflow-hidden">
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-5">
                <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" strokeWidth="1.6"><path d="M6 2H18L22 6V25A1 1 0 0121 26H6A1 1 0 015 25V3A1 1 0 016 2Z" /></svg>
                </div>
                <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">
                    SYSTEM LOGS
                </h2>
            </motion.div>

            <div className="flex-1 overflow-auto">
                <table className="w-full text-xs font-['Share_Tech_Mono']">
                    <caption className="sr-only">Blackwatch diagnostic and security log entries</caption>
                    <thead>
                        <tr className="border-b border-[rgba(0,240,255,0.2)]">
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider w-[140px]">TIME</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider w-[80px]">LEVEL</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider w-[120px]">SOURCE</th>
                            <th className="text-left py-2 px-3 text-[var(--cyan)] font-normal tracking-wider">MESSAGE</th>
                        </tr>
                    </thead>
                    <tbody>
                        {logs.length === 0 ? (
                            <tr><td colSpan={4} className="py-8 text-center text-[var(--text-dim)]">No logs yet</td></tr>
                        ) : visibleLogs.map((log, i) => (
                            <tr key={`${log.timestamp}-${log.source}-${safePage * pageSize + i}`} className="border-b border-[rgba(0,240,255,0.05)] hover:bg-[rgba(0,240,255,0.03)] transition-colors">
                                <td className="py-1.5 px-3 text-[var(--text-dim)]">{log.timestamp}</td>
                                <td className="py-1.5 px-3 font-bold" style={{ color: levelColor(log.level) }}>{log.level}</td>
                                <td className="py-1.5 px-3 text-[var(--text-dim)]">{log.source}</td>
                                <td className="py-1.5 px-3 text-[var(--text-primary)]">{log.message}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            {pageCount > 1 && (
                <div className="flex items-center justify-end gap-3 pt-2 text-xs font-['Share_Tech_Mono']" aria-label="Log table pagination">
                    <button type="button" disabled={safePage === 0} onClick={() => setPage(safePage - 1)} className="px-3 py-1 border border-[var(--cyan)] text-[var(--cyan)] disabled:opacity-40">PREVIOUS</button>
                    <span aria-live="polite">PAGE {safePage + 1} / {pageCount}</span>
                    <button type="button" disabled={safePage >= pageCount - 1} onClick={() => setPage(safePage + 1)} className="px-3 py-1 border border-[var(--cyan)] text-[var(--cyan)] disabled:opacity-40">NEXT</button>
                </div>
            )}
        </div>
    );
}
