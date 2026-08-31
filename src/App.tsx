import React from 'react';
import { LanguageProvider } from './hooks/useLanguage';
import { CyberBackground } from './components/CyberBackground';
import { CustomCursor } from './components/CustomCursor';
import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { ThreatVisualization } from './components/ThreatVisualization';
import { EngineSection } from './components/EngineSection';
import { PrivacySection } from './components/PrivacySection';
import { UpdatePipeline } from './components/UpdatePipeline';
import { Roadmap } from './components/Roadmap';
import { FAQ } from './components/FAQ';
import { DownloadSection } from './components/DownloadSection';
import { Footer } from './components/Footer';

export const App: React.FC = () => {
  return (
    <LanguageProvider>
      <div className="relative min-h-screen bg-background text-cyber-light font-body selection:bg-cyan selection:text-background">
        {/* Subtle Ambient Cyber Background */}
        <CyberBackground />

        {/* Custom Security Cursor (Desktop Only) */}
        <CustomCursor />

        {/* Top Sticky Navigation */}
        <Navbar />

        {/* Main Content Sections */}
        <main className="relative z-10">
          <Hero />
          <ThreatVisualization />
          <EngineSection />
          <PrivacySection />
          <UpdatePipeline />
          <Roadmap />
          <FAQ />
          <DownloadSection />
        </main>

        {/* Global Footer */}
        <Footer />
      </div>
    </LanguageProvider>
  );
};
