import React from 'react';

export const CyberBackground: React.FC = () => {
  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden" aria-hidden="true">
      {/* Deep Cyber Gradient Mesh */}
      <div className="absolute inset-0 bg-background" />

      {/* Grid Pattern */}
      <div className="absolute inset-0 cyber-grid opacity-70" />
      <div className="absolute inset-0 cyber-dots opacity-40" />

      {/* Ambient Volumetric Glow Orbs */}
      <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-cyan/5 blur-[140px]" />
      <div className="absolute top-1/3 -right-40 w-[600px] h-[600px] rounded-full bg-emerald/5 blur-[160px]" />
      <div className="absolute bottom-20 left-1/4 w-[500px] h-[500px] rounded-full bg-cyan/4 blur-[150px]" />

      {/* Subtle Horizontal Scanning Scanline */}
      <div 
        className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-cyan/20 to-transparent animate-pulse-slow"
        style={{ top: '25%' }}
      />
    </div>
  );
};
