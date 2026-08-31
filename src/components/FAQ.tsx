import React, { useState } from 'react';
import { HelpCircle, ChevronDown } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const FAQ: React.FC = () => {
  const { t } = useLanguage();
  const [openIdx, setOpenIdx] = useState<number | null>(0);

  const faqItems = [
    { q: t.faq_q1, a: t.faq_a1 },
    { q: t.faq_q2, a: t.faq_a2 },
    { q: t.faq_q3, a: t.faq_a3 },
    { q: t.faq_q4, a: t.faq_a4 },
    { q: t.faq_q5, a: t.faq_a5 },
  ];

  const toggle = (idx: number) => {
    setOpenIdx(openIdx === idx ? null : idx);
  };

  return (
    <section id="faq" className="py-24 relative overflow-hidden">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center space-y-4 mb-14">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/10 text-cyan text-xs font-mono tracking-wider uppercase">
            <HelpCircle className="w-3.5 h-3.5" />
            <span>{t.faq_badge}</span>
          </div>
          <h2 className="font-display font-bold text-3xl sm:text-4xl text-white tracking-tight">
            {t.faq_title}
          </h2>
        </div>

        {/* Accordion List */}
        <div className="space-y-4">
          {faqItems.map((item, idx) => {
            const isOpen = openIdx === idx;
            return (
              <div
                key={idx}
                className={`rounded-2xl border transition-all duration-300 overflow-hidden ${
                  isOpen 
                    ? 'glass-panel border-cyan/40 shadow-cyber-cyan' 
                    : 'glass-panel border-white/10 hover:border-white/20'
                }`}
              >
                <button
                  onClick={() => toggle(idx)}
                  className="w-full p-6 text-left flex items-center justify-between gap-4 font-display font-semibold text-base sm:text-lg text-white"
                  aria-expanded={isOpen}
                >
                  <span>{item.q}</span>
                  <ChevronDown className={`w-5 h-5 text-cyan shrink-0 transition-transform duration-300 ${
                    isOpen ? 'rotate-180' : 'rotate-0'
                  }`} />
                </button>

                {isOpen && (
                  <div className="px-6 pb-6 pt-1 text-sm text-cyber-slate leading-relaxed border-t border-white/5 font-body">
                    {item.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
};
