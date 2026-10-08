import React, { useState } from 'react';
import { Layers, Binary, Hash, FolderArchive, ChevronRight, Activity, ShieldCheck, Zap } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const EngineSection: React.FC = () => {
  const { t } = useLanguage();
  const [selectedLayer, setSelectedLayer] = useState<number>(0);

  const layers = [
    {
      num: '01',
      id: 'yara',
      title: t.layer1_title,
      desc: t.layer1_desc,
      tech: t.layer1_tech,
      icon: Layers,
      color: 'cyan',
    },
    {
      num: '02',
      id: 'clamav',
      title: t.layer2_title,
      desc: t.layer2_desc,
      tech: t.layer2_tech,
      icon: Binary,
      color: 'emerald',
    },
    {
      num: '03',
      id: 'hash',
      title: t.layer3_title,
      desc: t.layer3_desc,
      tech: t.layer3_tech,
      icon: Hash,
      color: 'cyan',
    },
    {
      num: '04',
      id: 'zip',
      title: t.layer4_title,
      desc: t.layer4_desc,
      tech: t.layer4_tech,
      icon: FolderArchive,
      color: 'emerald',
    },
  ];

  return (
    <section id="engine" className="py-24 relative overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/10 text-cyan text-xs font-mono tracking-wider uppercase">
            <Zap className="w-3.5 h-3.5" />
            <span>{t.engine_badge}</span>
          </div>
          <h2 className="font-display font-bold text-3xl sm:text-4xl text-white tracking-tight">
            {t.engine_title}
          </h2>
          <p className="text-cyber-slate text-sm sm:text-base leading-relaxed">
            {t.engine_desc}
          </p>
        </div>

        {/* 4-Layer Interactive Architecture Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 mt-16 items-center">
          
          {/* Left: Layer Selector Cards */}
          <div className="lg:col-span-6 space-y-4">
            {layers.map((layer, idx) => {
              const Icon = layer.icon;
              const isSelected = selectedLayer === idx;

              return (
                <div
                  key={layer.id}
                  onClick={() => setSelectedLayer(idx)}
                  className={`p-6 rounded-2xl border cursor-pointer transition-all duration-300 relative overflow-hidden ${
                    isSelected
                      ? 'border-cyan bg-cyan/10 shadow-cyber-cyan translate-x-2'
                      : 'border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-center gap-4">
                      <div className={`p-3 rounded-xl border ${
                        isSelected 
                          ? 'border-cyan bg-cyan/20 text-cyan' 
                          : 'border-white/10 bg-white/5 text-cyber-slate'
                      }`}>
                        <Icon className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-cyan tracking-widest">
                            LAYER {layer.num}
                          </span>
                          <span className="text-xs text-white/30">•</span>
                          <span className="text-xs font-mono text-cyber-muted">{layer.tech}</span>
                        </div>
                        <h3 className="font-display font-bold text-lg text-white mt-1">
                          {layer.title}
                        </h3>
                      </div>
                    </div>
                    <ChevronRight className={`w-5 h-5 transition-transform ${isSelected ? 'text-cyan rotate-90' : 'text-cyber-muted'}`} />
                  </div>
                  <p className="text-xs sm:text-sm text-cyber-slate mt-3 leading-relaxed">
                    {layer.desc}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Right: 3D Exploded Layer Deep Inspector HUD */}
          <div className="lg:col-span-6 glass-panel-glow p-8 rounded-3xl relative overflow-hidden border border-cyan/30">
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan animate-pulse" />
                <span className="font-mono text-xs font-bold text-cyan uppercase tracking-widest">
                  LAYER_INSPECTION_HUD
                </span>
              </div>
              <span className="font-mono text-xs text-cyber-muted">
                ACTIVE_INDEX: 0{selectedLayer + 1}
              </span>
            </div>

            {/* Interactive Hologram View */}
            <div className="my-8 py-10 flex flex-col items-center justify-center text-center space-y-4">
              <div className="relative w-28 h-28 rounded-3xl border-2 border-cyan/40 bg-cyan/10 flex items-center justify-center text-cyan shadow-cyber-cyan animate-float">
                {React.createElement(layers[selectedLayer].icon, { className: 'w-14 h-14' })}
                <div className="absolute inset-0 rounded-3xl border border-dashed border-emerald/50 animate-spin-slow" />
              </div>
              <div>
                <span className="font-mono text-xs text-emerald tracking-widest uppercase">
                  ACTIVE SCAN PROTOCOL
                </span>
                <h4 className="font-display font-bold text-2xl text-white mt-1">
                  {layers[selectedLayer].title}
                </h4>
                <p className="font-mono text-xs text-cyber-slate mt-2 max-w-sm">
                  {layers[selectedLayer].tech}
                </p>
              </div>
            </div>

            {/* Micro Specifications */}
            <div className="grid grid-cols-2 gap-3 pt-4 border-t border-white/10 text-xs font-mono">
              <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
                <span className="text-cyber-muted text-[10px] uppercase">EXECUTION_CONTEXT</span>
                <p className="text-emerald font-semibold">100% On-Device Memory</p>
              </div>
              <div className="p-3 rounded-xl bg-black/40 border border-white/5 space-y-1">
                <span className="text-cyber-muted text-[10px] uppercase">LATENCY</span>
                <p className="text-cyan font-semibold">&lt; 150ms per APK</p>
              </div>
            </div>

          </div>

        </div>

      </div>
    </section>
  );
};
