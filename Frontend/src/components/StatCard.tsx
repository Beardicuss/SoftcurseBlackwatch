import { motion } from 'framer-motion';
interface StatCardProps {
  label: string;
  value: string;
  unit?: string;
  progress?: number;
  variant?: 'cyan' | 'magenta';
}
export function StatCard({
  label,
  value,
  unit,
  progress,
  variant = 'cyan'
}: StatCardProps) {
  const isMagenta = variant === 'magenta';
  const borderColor = isMagenta ?
  'border-[var(--magenta)]' :
  'border-[var(--cyan)]';
  const glowClass = isMagenta ? 'glow-magenta' : 'glow-cyan';
  const textColor = isMagenta ? 'text-[var(--magenta)]' : 'text-[var(--cyan)]';
  const textGlow = isMagenta ? 'text-glow-magenta' : 'text-glow-cyan';
  const cornerColor = isMagenta ? 'var(--magenta)' : 'var(--cyan)';
  return (
    <motion.div
      initial={{
        opacity: 0,
        y: 20
      }}
      animate={{
        opacity: 1,
        y: 0
      }}
      className={`tech-card ${isMagenta ? 'magenta' : ''} border ${borderColor} ${glowClass} p-4 min-w-[140px]`}>

      {/* All 4 corner accents */}
      <span
        className="corner corner-tl"
        style={{
          borderColor: cornerColor
        }} />

      <span
        className="corner corner-tr"
        style={{
          borderColor: cornerColor
        }} />

      <span
        className="corner corner-bl"
        style={{
          borderColor: cornerColor
        }} />

      <span
        className="corner corner-br"
        style={{
          borderColor: cornerColor
        }} />


      {/* Label */}
      <p className="text-xs text-[var(--text-dim)] tracking-wider mb-2 font-['Share_Tech_Mono']">
        {label}
      </p>

      {/* Value */}
      <div className="flex items-baseline gap-1">
        <motion.span
          className={`text-3xl font-bold ${textColor} ${textGlow} font-['Orbitron']`}
          initial={{
            opacity: 0
          }}
          animate={{
            opacity: 1
          }}
          transition={{
            delay: 0.2
          }}>

          {value}
        </motion.span>
        {unit &&
        <span
          className={`text-base ${textColor} font-['Share_Tech_Mono'] ml-1`}>

            {unit}
          </span>
        }
      </div>

      {/* Progress bar */}
      {progress !== undefined &&
      <div className="mt-3 h-1 bg-[rgba(0,0,0,0.4)] overflow-hidden">
          <motion.div
          className={`h-full ${isMagenta ? 'bg-[var(--magenta)]' : 'bg-[var(--cyan)]'}`}
          initial={{
            width: 0
          }}
          animate={{
            width: `${progress}%`
          }}
          transition={{
            duration: 1,
            ease: 'easeOut',
            delay: 0.3
          }}
          style={{
            boxShadow: isMagenta ?
            '0 0 10px var(--magenta), 0 0 20px var(--magenta)' :
            '0 0 10px var(--cyan), 0 0 20px var(--cyan)'
          }} />

        </div>
      }
    </motion.div>);

}
