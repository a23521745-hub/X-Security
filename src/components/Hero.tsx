import React from 'react';
import { Download, Github, ShieldCheck, Cpu, HardDrive, Lock, Sparkles } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';
import { SecurityCoreScene } from './3d/SecurityCoreScene';

export const Hero: React.FC = () => {
  const { t } = useLanguage();

  const trustBadges = [
    { label: t.trust_open_source, icon: Sparkles },
    { label: t.trust_android, icon: Cpu },
    { label: t.trust_size, icon: HardDrive },
    { label: t.trust_privacy, icon: Lock },
  ];

  const stats = [
    { val: t.stat_layers_val, label: t.stat_layers_label, color: 'text-cyan' },
    { val: t.stat_hashes_val, label: t.stat_hashes_label, color: 'text-emerald' },
    { val: t.stat_signatures_val, label: t.stat_signatures_label, color: 'text-cyan' },
    { val: t.stat_telemetry_val, label: t.stat_telemetry_label, color: 'text-emerald' },
  ];

  return (
    <section id="hero" className="relative min-h-screen pt-28 pb-16 flex flex-col justify-center overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full z-10">
        
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
          
          {/* Left Column: Headline & Controls */}
          <div className="lg:col-span-7 space-y-6 text-center lg:text-left">
            
            {/* Tactical Eyebrow Badge */}
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-cyan/30 bg-cyan/10 backdrop-blur-md">
              <span className="w-2 h-2 rounded-full bg-cyan animate-pulse" />
              <span className="text-xs font-mono font-medium tracking-wider text-cyan uppercase">
                {t.hero_badge}
              </span>
            </div>

            {/* Main H1 Headline */}
            <h1 className="font-display font-extrabold text-4xl sm:text-5xl lg:text-6xl text-white tracking-tight leading-[1.1]">
              <span className="block">{t.hero_title}</span>
              <span className="gradient-text-cyan mt-1 block">X-Security</span>
            </h1>

            {/* Subtitle */}
            <p className="text-base sm:text-lg text-cyber-slate max-w-2xl mx-auto lg:mx-0 leading-relaxed font-body">
              {t.hero_sub}
            </p>

            {/* Dual CTAs */}
            <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4 pt-2">
              <a
                href="https://github.com/a23521745-hub/X-Security/releases/latest"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2.5 px-6 py-3.5 rounded-xl font-display font-bold text-sm uppercase tracking-wider text-background bg-gradient-to-r from-cyan via-teal-400 to-emerald hover:shadow-cyber-cyan hover:scale-[1.02] active:scale-[0.98] transition-all duration-300"
              >
                <Download className="w-4 h-4" />
                <span>{t.hero_cta_download}</span>
              </a>

              <a
                href="https://github.com/a23521745-hub/X-Security"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2.5 px-6 py-3.5 rounded-xl font-display font-semibold text-sm tracking-wider text-white border border-white/10 bg-white/5 hover:border-cyan/40 hover:bg-cyan/5 transition-all duration-300"
              >
                <Github className="w-4 h-4" />
                <span>{t.hero_cta_github}</span>
              </a>
            </div>

            {/* Trust Pill Row */}
            <div className="pt-4 flex flex-wrap items-center justify-center lg:justify-start gap-2.5">
              {trustBadges.map((badge, idx) => {
                const Icon = badge.icon;
                return (
                  <div
                    key={idx}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border border-white/5 bg-white/[0.02] text-xs font-mono text-cyber-muted hover:text-cyber-light transition-colors"
                  >
                    <Icon className="w-3.5 h-3.5 text-cyan" />
                    <span>{badge.label}</span>
                  </div>
                );
              })}
            </div>

          </div>

          {/* Right Column: 3D Security Core Visual Scene */}
          <div className="lg:col-span-5 flex items-center justify-center relative">
            <SecurityCoreScene />
          </div>

        </div>

        {/* HUD Stats Row */}
        <div className="mt-16 pt-10 border-t border-white/10 grid grid-cols-2 md:grid-cols-4 gap-6">
          {stats.map((stat, idx) => (
            <div key={idx} className="glass-panel p-5 rounded-2xl text-center space-y-1 relative overflow-hidden group hover:border-cyan/30 transition-all duration-300">
              <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-cyan/20 to-transparent group-hover:via-cyan/60 transition-all duration-300" />
              <div className={`font-display font-bold text-3xl sm:text-4xl ${stat.color} tracking-tight`}>
                {stat.val}
              </div>
              <div className="text-xs font-mono text-cyber-slate leading-tight">
                {stat.label}
              </div>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
};
