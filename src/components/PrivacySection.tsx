import React from 'react';
import { Smartphone, ShieldOff, EyeOff, UserX, Code2, Lock, ShieldCheck, XCircle } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const PrivacySection: React.FC = () => {
  const { t } = useLanguage();

  const privacyFeatures = [
    {
      icon: Smartphone,
      title: t.priv_c1_title,
      desc: t.priv_c1_desc,
    },
    {
      icon: UserX,
      title: t.priv_c2_title,
      desc: t.priv_c2_desc,
    },
    {
      icon: EyeOff,
      title: t.priv_c3_title,
      desc: t.priv_c3_desc,
    },
    {
      icon: Code2,
      title: t.priv_c4_title,
      desc: t.priv_c4_desc,
    },
  ];

  return (
    <section id="privacy" className="py-24 relative overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald/30 bg-emerald/10 text-emerald text-xs font-mono tracking-wider uppercase">
            <Lock className="w-3.5 h-3.5" />
            <span>{t.privacy_badge}</span>
          </div>
          <h2 className="font-display font-bold text-3xl sm:text-4xl text-white tracking-tight">
            {t.privacy_title}
          </h2>
          <p className="text-cyber-slate text-sm sm:text-base leading-relaxed">
            {t.privacy_desc}
          </p>
        </div>

        {/* 3D Device Sandbox Representation & Telemetry Blocker */}
        <div className="mt-16 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
          
          {/* Left: 3D Holographic Device Mockup */}
          <div className="lg:col-span-5 flex justify-center">
            <div className="relative w-64 sm:w-72 h-[420px] rounded-[36px] border-2 border-emerald/40 bg-gradient-to-b from-emerald/10 via-background to-black/80 p-4 shadow-cyber-emerald flex flex-col justify-between">
              
              {/* Device Notch */}
              <div className="w-24 h-4 bg-white/10 rounded-full mx-auto" />

              {/* Local Sandbox Boundary Visual */}
              <div className="border border-dashed border-emerald/50 rounded-2xl p-4 my-auto text-center space-y-3 bg-emerald/5">
                <div className="w-12 h-12 rounded-xl bg-emerald/20 border border-emerald text-emerald mx-auto flex items-center justify-center animate-pulse">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <div className="font-mono text-xs font-bold text-emerald uppercase tracking-wider">
                  ISOLATED_DEVICE_SANDBOX
                </div>
                <div className="space-y-1 text-[11px] font-mono text-cyber-slate">
                  <p className="text-white font-semibold">LOCAL MEMORY SCAN</p>
                  <p>YARA • ClamAV • Hash DB</p>
                </div>
              </div>

              {/* Blocked Outgoing Telemetry Vector */}
              <div className="p-3 rounded-xl bg-danger/10 border border-danger/30 flex items-center justify-between text-xs font-mono text-danger">
                <div className="flex items-center gap-2">
                  <XCircle className="w-4 h-4" />
                  <span>CLOUD_TELEMETRY</span>
                </div>
                <span className="font-bold uppercase tracking-wider">BLOCKED</span>
              </div>

            </div>
          </div>

          {/* Right: 4 Privacy Pillars */}
          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {privacyFeatures.map((feat, idx) => {
              const Icon = feat.icon;
              return (
                <div 
                  key={idx}
                  className="glass-panel p-6 rounded-2xl border border-white/10 hover:border-emerald/40 hover:bg-emerald/[0.03] transition-all duration-300 space-y-3"
                >
                  <div className="w-10 h-10 rounded-xl bg-emerald/10 border border-emerald/30 text-emerald flex items-center justify-center">
                    <Icon className="w-5 h-5" />
                  </div>
                  <h3 className="font-display font-semibold text-lg text-white">
                    {feat.title}
                  </h3>
                  <p className="text-xs sm:text-sm text-cyber-slate leading-relaxed">
                    {feat.desc}
                  </p>
                </div>
              );
            })}
          </div>

        </div>

      </div>
    </section>
  );
};
