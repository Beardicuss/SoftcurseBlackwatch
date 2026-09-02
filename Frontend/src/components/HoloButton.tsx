import type { ReactNode } from 'react';
interface HoloButtonProps {
  children: ReactNode;
  icon?: ReactNode;
  variant?: 'cyan' | 'magenta';
  onClick?: () => void;
}
export function HoloButton({
  children,
  icon,
  variant = 'cyan',
  onClick
}: HoloButtonProps) {
  const isMagenta = variant === 'magenta';
  return (
    <div className="holo-btn-wrapper">
      <button
        onClick={onClick}
        className={`holo-btn ${isMagenta ? 'holo-btn-magenta' : 'holo-btn-cyan'}`}>

        <span className="holo-btn-text">
          {icon && <span className="holo-btn-icon">{icon}</span>}
          {children}
        </span>
        <div className="holo-btn-glow" />
        <div className="holo-btn-glitch" />
        <div className="holo-btn-corners">
          <span className="holo-btn-corner" />
          <span className="holo-btn-corner" />
          <span className="holo-btn-corner" />
          <span className="holo-btn-corner" />
        </div>
        <div className="holo-btn-lines">
          <span className="holo-btn-line" />
          <span className="holo-btn-line" />
          <span className="holo-btn-line" />
          <span className="holo-btn-line" />
        </div>
        <div className="holo-btn-scan" />
        <div className="holo-btn-particles">
          {[...Array(6)].map((_, i) =>
          <span key={i} className="holo-btn-particle" />
          )}
        </div>
      </button>
    </div>);

}
