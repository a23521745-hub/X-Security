import React from 'react';
import { KeyRound, ShieldCheck, CheckCheck, RefreshCw, Radio, ExternalLink } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const UpdatePipeline: React.FC = () => {
  const { t } = useLanguage();

  const pipelineNodes = [
    {
      step: '01',
      title: t.pipe_s1_title,
      desc: t.pipe_s1_desc,
      icon: KeyRound,
      color: 'border-cyan/40 text-cyan bg-cyan/10',
    },
    {
      step: '02',
      title: t.pipe_s2_title,
      desc: t.pipe_s2_desc,
      icon: CheckCheck,
      color: 'border-emerald/40 text-emerald bg-emerald/10',
    },
    {
      step: '03',
      title: t.pipe_s3_title,
      desc: t.pipe_s3_desc,
      icon: RefreshCw,
      color: 'border-cyan/40 text-cyan bg-cyan/10',
    },
    {
      step: '04',
      title: t.pipe_s4_title,
      desc: t.pipe_s4_desc,
      icon: Radio,
      color: 'border-emerald/40 text-emerald bg-emerald/10',
    },
  ];

  return (
    <section id="pipeline" className="py-24 relative overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/10 text-cyan text-xs font-mono tracking-wider uppercase">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{t.pipeline_badge}</span>
          </div>
          <h2 className="font-display font-bold text-3xl sm:text-4xl text-white tracking-tight">
            {t.pipeline_title}
          </h2>
          <p className="text-cyber-slate text-sm sm:text-base leading-relaxed">
            {t.pipeline_desc}
          </p>
        </div>

        {/* 4-Stage Secure Pipeline Architecture */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mt-16">
          {pipelineNodes.map((node, idx) => {
            const Icon = node.icon;
            return (
              <div
                key={idx}
                className="glass-panel p-6 rounded-2xl border border-white/10 hover:border-cyan/40 relative overflow-hidden group space-y-4 transition-all duration-300"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyan tracking-widest">
                    STAGE {node.step}
                  </span>
                  <div className={`p-2.5 rounded-xl border ${node.color} group-hover:scale-110 transition-transform duration-300`}>
                    <Icon className="w-5 h-5" />
                  </div>
                </div>

                <h3 className="font-display font-semibold text-lg text-white">
                  {node.title}
                </h3>

                <p className="text-xs sm:text-sm text-cyber-slate leading-relaxed">
                  {node.desc}
                </p>

                {/* Micro Progress Track */}
                <div className="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-cyan to-emerald w-full animate-pulse" />
                </div>
              </div>
            );
          })}
        </div>

        {/* Echap Stalkerware Attribution Box */}
        <div className="mt-12 p-4 rounded-2xl glass-panel border border-cyan/20 flex flex-col sm:flex-row items-center justify-between gap-4 text-center sm:text-left">
          <div className="space-y-1">
            <p className="text-xs font-mono text-cyan uppercase tracking-wider font-semibold">
              COMMUNITY THREAT INTELLIGENCE PARTNERSHIP
            </p>
            <p className="text-xs text-cyber-slate">
              {t.pipe_attribution}
            </p>
          </div>
          <a
            href="https://github.com/AssoEchap/stalkerware-indicators"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 text-xs font-mono text-cyber-light hover:text-cyan hover:border-cyan/40 transition-colors"
          >
            <span>AssoEchap Repo</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>

      </div>
    </section>
  );
};
