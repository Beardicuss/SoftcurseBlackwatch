import { useState, useEffect } from 'react';
import { ScanIcon, Trash2Icon } from 'lucide-react';
import { motion } from 'framer-motion';
import { HoloButton } from './HoloButton';
import { sendBridgeCommand } from '../bridge';

export function StatusBar() {
  const [statusText, setStatusText] = useState('INITIALIZING MONITORING...');
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    // Listen for status updates from Dashboard bridge
    window.updateStatusBar = (text: string, scanning: boolean) => {
      setStatusText(text);
      setIsScanning(scanning);
    };
    return () => { delete window.updateStatusBar; };
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.5 }}
      className="h-16 bg-[var(--bg-card)] border-t border-[rgba(0,240,255,0.2)] flex items-center justify-between px-5 relative">

      {/* Subtle circuit pattern */}
      <div className="absolute inset-0 circuit-pattern opacity-20" />

      {/* Status message */}
      <div className="flex items-center gap-3 relative z-10">
        <motion.div
          animate={{
            scale: [1, 1.1, 1],
            opacity: [0.8, 1, 0.8]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: 'easeInOut'
          }}
          className="relative">

          <svg width="24" height="24" viewBox="0 0 24 24" fill="none"
            style={{ filter: 'drop-shadow(0 0 6px var(--cyan)) drop-shadow(0 0 12px var(--cyan))' }}>
            <circle cx="12" cy="12" r="10" stroke="var(--cyan)" strokeWidth="2" fill="none" opacity="0.6" />
            <path d="M12 2 A10 10 0 0 1 12 22" fill="var(--cyan)" opacity="0.4" />
            <circle cx="12" cy="12" r="3" fill="var(--cyan)" />
          </svg>
        </motion.div>
        <span className="text-xs tracking-wider text-[var(--text-primary)] font-['Share_Tech_Mono']">
          {statusText}
        </span>
        {isScanning && (
          <motion.div
            animate={{ opacity: [0.3, 1, 0.3] }}
            transition={{ duration: 0.6, repeat: Infinity }}
            className="w-2 h-2 rounded-full bg-[var(--cyan)]"
          />
        )}
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-3 relative z-10">
        <HoloButton variant="cyan" icon={<ScanIcon size={14} />} onClick={() => sendBridgeCommand({ type: 'app', action: 'scan' })}>
          SCAN NOW
        </HoloButton>
        <HoloButton variant="magenta" icon={<Trash2Icon size={14} />} onClick={() => sendBridgeCommand({ type: 'app', action: 'purge' })}>
          PURGE
        </HoloButton>
      </div>
    </motion.div>);
}
