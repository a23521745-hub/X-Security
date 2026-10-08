import React from 'react';
import { Shield, ShieldAlert } from 'lucide-react';

interface CanvasFallbackProps {
  threatMode?: boolean;
}

export const CanvasFallback: React.FC<CanvasFallbackProps> = ({ threatMode = false }) => {
  return (
    <div className="relative w-full h-full min-h-[350px] flex items-center justify-center">
      {/* Outer Glow Orb */}
      <div 
        className={`absolute w-72 h-72 rounded-full blur-3xl opacity-20 pointer-events-none ${
          threatMode ? 'bg-danger' : 'bg-cyan'
        }`} 
      />

      {/* Rotating Cyber Rings */}
      <div className="relative w-64 h-64 md:w-80 md:h-80 rounded-full flex items-center justify-center">
        {/* Ring 1 */}
        <div 
          className={`absolute inset-0 rounded-full border border-dashed animate-spin-slow ${
            threatMode ? 'border-danger/40' : 'border-cyan/40'
          }`} 
        />
        {/* Ring 2 */}
        <div 
          className={`absolute inset-6 rounded-full border border-dotted ${
            threatMode ? 'border-orange-500/40' : 'border-emerald/40'
          }`}
          style={{ animation: 'spin 15s linear infinite reverse' }}
        />
        {/* Ring 3 (Radar Sweep) */}
        <div 
          className="absolute inset-12 rounded-full opacity-30 animate-radar-sweep pointer-events-none"
          style={{
            background: threatMode 
              ? 'conic-gradient(from 0deg, transparent 0deg, rgba(244,63,94,0.3) 30deg, transparent 60deg)'
              : 'conic-gradient(from 0deg, transparent 0deg, rgba(34,211,238,0.3) 30deg, transparent 60deg)',
          }}
        />

        {/* Center Shield Core */}
        <div className={`relative z-10 p-6 rounded-2xl border backdrop-blur-xl transition-all duration-500 ${
          threatMode 
            ? 'border-danger/40 bg-danger-dim text-danger shadow-cyber-danger' 
            : 'border-cyan/40 bg-cyan-dim text-cyan shadow-cyber-cyan'
        }`}>
          {threatMode ? (
            <ShieldAlert className="w-16 h-16 md:w-20 md:h-20 animate-pulse" />
          ) : (
            <Shield className="w-16 h-16 md:w-20 md:h-20" />
          )}
        </div>
      </div>
    </div>
  );
};
