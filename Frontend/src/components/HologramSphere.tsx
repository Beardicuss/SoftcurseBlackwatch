import { useEffect, useState } from 'react';

interface HologramSphereProps {
  threatActive?: boolean;
}

export function HologramSphere({ threatActive }: HologramSphereProps) {
  const [hasThreats, setHasThreats] = useState(false);

  useEffect(() => {
    // Listen for global threat state updates
    (window as any).updateThreatState = (active: boolean) => {
      setHasThreats(active);
    };
    return () => { delete (window as any).updateThreatState; };
  }, []);

  const isAlert = threatActive || hasThreats;

  return (
    <div className={`holo-loader-container ${isAlert ? 'holo-threat-active' : ''}`}
      style={isAlert ? { '--holo-color': '#ff2244', '--holo-rgb': '255, 34, 68' } as React.CSSProperties : {}}>
      {/* Platform glow */}
      <div className="holo-platform" />

      {/* Platform rings */}
      <div className="holo-platform-rings">
        <div className="holo-platform-ring" />
        <div className="holo-platform-ring" />
        <div className="holo-platform-ring" />
      </div>

      {/* Projection beams */}
      <div className="holo-projection-beams">
        <div className="holo-beam" />
        <div className="holo-beam" />
        <div className="holo-beam" />
        <div className="holo-beam" />
      </div>

      {/* Main hologram */}
      <div className="holo-float-container">
        <div className="holo-sphere-element">
          <div className="holo-sphere-ring" />
          <div className="holo-sphere-ring" />
          <div className="holo-sphere-ring" />
          <div className="holo-sphere-ring" />
          <div className="holo-sphere-ring" />
          <div className="holo-sphere-particles">
            {[...Array(12)].map((_, i) =>
              <div key={i} className="holo-sphere-particle" />
            )}
          </div>
        </div>
        <div className="holo-glitch-fx" />
        <div className="holo-lightning-fx" />
      </div>

      {/* Alert text when threats detected */}
      {isAlert && (
        <div style={{
          position: 'absolute',
          bottom: '12%',
          left: '50%',
          transform: 'translateX(-50%)',
          color: '#ff2244',
          fontSize: '8px',
          fontFamily: 'Share Tech Mono, Consolas, monospace',
          letterSpacing: '2px',
          textShadow: '0 0 8px rgba(255,34,68,0.8)',
          animation: 'borderPulse 1s ease-in-out infinite',
          zIndex: 10,
        }}>
          ⚠ THREAT
        </div>
      )}

      {/* Code lines */}
      <div className="holo-code-lines">
        <div className="holo-code-line">
          01001001 01001110 01001001 01010100
        </div>
        <div className="holo-code-line">initHolographicMatrix()</div>
        <div className="holo-code-line">
          01010011 01011001 01010011 01010100
        </div>
        <div className="holo-code-line">quantum.entangle()</div>
        <div className="holo-code-line">
          01010010 01000101 01001110 01000100
        </div>
        <div className="holo-code-line">matrix = [1.2, 0.8, 3.1]</div>
      </div>

      {/* Floating hex numbers */}
      <div className="holo-numbers-container">
        <div className="holo-float-number" style={{ top: '40%', left: '30%', animationDelay: '0.5s' }}>0xFF</div>
        <div className="holo-float-number" style={{ top: '50%', left: '60%', animationDelay: '1.5s' }}>0x0A</div>
        <div className="holo-float-number" style={{ top: '60%', left: '40%', animationDelay: '2.5s' }}>0xB4</div>
        <div className="holo-float-number" style={{ top: '30%', left: '50%', animationDelay: '3.5s' }}>0x3D</div>
      </div>

      {/* Radial indicators */}
      <div className="holo-radial-indicators">
        <div className="holo-radial-indicator" />
        <div className="holo-radial-indicator" />
        <div className="holo-radial-indicator" />
        <div className="holo-radial-indicator" />
      </div>

      {/* Corner decorations */}
      <div className="holo-corner-decorations">
        <div className="holo-corner" />
        <div className="holo-corner" />
        <div className="holo-corner" />
        <div className="holo-corner" />
      </div>
    </div>);
}