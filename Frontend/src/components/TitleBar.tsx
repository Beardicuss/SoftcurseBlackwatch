import { MinusIcon, SquareIcon, XIcon } from 'lucide-react';
import { sendBridgeCommand } from '../bridge';

export function TitleBar() {
  return (
    <div
      className="h-8 bg-[#0a0e14] flex items-center justify-between px-3 border-b border-[rgba(0,240,255,0.1)] select-none"
      onMouseDown={(e) => {
        // Only drag on left-click, not on buttons
        if (e.button === 0 && (e.target as HTMLElement).closest('button') === null) {
          sendBridgeCommand({ type: 'window', action: 'dragstart' });
        }
      }}
    >
      {/* Left side - App title */}
      <div className="flex items-center gap-2">
        <div
          className="w-2.5 h-2.5 rounded-full bg-[#00ff88]"
          style={{
            boxShadow:
              '0 0 6px rgba(0,255,136,0.8), 0 0 12px rgba(0,255,136,0.4)'
          }} />

        <span className="text-[10px] tracking-widest text-[var(--text-dim)] font-['Share_Tech_Mono']">
          SOFTCURSE BLACKWATCH
        </span>
        <span className="text-[8px] tracking-[0.16em] text-[rgba(0,240,255,0.42)] font-['Share_Tech_Mono'] border-l border-[rgba(0,240,255,0.18)] pl-2">
          CREATED BY SOFTCURSE
        </span>
      </div>

      {/* Right side - Window controls */}
      <div className="flex items-center gap-0">
        <button
          onClick={() => sendBridgeCommand({ type: 'window', action: 'minimize' })}
          className="w-10 h-8 flex items-center justify-center text-[var(--text-dim)] hover:bg-[rgba(255,255,255,0.05)] transition-colors"
          aria-label="Minimize">
          <MinusIcon size={12} strokeWidth={1.5} />
        </button>
        <button
          onClick={() => sendBridgeCommand({ type: 'window', action: 'maximize' })}
          className="w-10 h-8 flex items-center justify-center text-[var(--text-dim)] hover:bg-[rgba(255,255,255,0.05)] transition-colors"
          aria-label="Maximize">
          <SquareIcon size={10} strokeWidth={1.5} />
        </button>
        <button
          onClick={() => sendBridgeCommand({ type: 'window', action: 'close' })}
          className="w-10 h-8 flex items-center justify-center text-[var(--text-dim)] hover:bg-red-600 hover:text-white transition-colors"
          aria-label="Close">
          <XIcon size={12} strokeWidth={1.5} />
        </button>
      </div>
    </div>);
}
