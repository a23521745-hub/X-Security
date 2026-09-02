import React from 'react';
import { Milestone, Clock, ShieldAlert, Download, Archive, CheckCircle2 } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const Roadmap: React.FC = () => {
  const { t } = useLanguage();

  const steps = [
    {
      num: '01',
      title: t.road_step1_title,
      desc: t.road_step1_desc,
      icon: CheckCircle2,
      badge: t.badge_coming_soon,
      status: 'active',
    },
    {
      num: '02',
      title: t.road_step2_title,
      desc: t.road_step2_desc,
      icon: ShieldAlert,
      badge: t.badge_coming_soon,
      status: 'pending',
    },
    {
      num: '03',
      title: t.road_step3_title,
      desc: t.road_step3_desc,
      icon: Download,
      badge: t.badge_coming_soon,
      status: 'pending',
    },
    {
      num: '04',
      title: t.road_step4_title,
      desc: t.road_step4_desc,
      icon: Archive,
      badge: t.badge_coming_soon,
      status: 'pending',
    },
  ];

  return (
    <section id="roadmap" className="py-24 relative overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/10 text-cyan text-xs font-mono tracking-wider uppercase">
            <Milestone className="w-3.5 h-3.5" />
            <span>{t.roadmap_badge}</span>
          </div>
          <h2 className="font-display font-bold text-3xl sm:text-4xl text-white tracking-tight">
            {t.roadmap_title}
          </h2>
          <p className="text-cyber-slate text-sm sm:text-base leading-relaxed">
            {t.roadmap_desc}
          </p>
        </div>

        {/* Horizontal Timeline Track */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-16 relative">
          
          {/* Connector Line behind cards for large screens */}
          <div className="hidden lg:block absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan via-emerald to-cyan/30 -translate-y-8 z-0 opacity-40" />

          {steps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div
                key={idx}
                className="glass-panel p-6 rounded-2xl border border-white/10 hover:border-cyan/40 space-y-4 relative z-10 group hover:-translate-y-1.5 transition-all duration-300"
              >
                <div className="flex items-center justify-between">
                  <div className="w-10 h-10 rounded-xl bg-cyan/10 border border-cyan/30 text-cyan flex items-center justify-center font-mono font-bold text-sm">
                    {step.num}
                  </div>
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald/10 border border-emerald/30 text-[10px] font-mono font-bold text-emerald uppercase">
                    <Clock className="w-3 h-3" />
                    <span>{step.badge}</span>
                  </span>
                </div>

                <h3 className="font-display font-semibold text-lg text-white group-hover:text-cyan transition-colors">
                  {step.title}
                </h3>

                <p className="text-xs sm:text-sm text-cyber-slate leading-relaxed">
                  {step.desc}
                </p>
              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
};
