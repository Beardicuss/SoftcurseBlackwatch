import { TitleBar } from './components/TitleBar';
import { Sidebar } from './components/Sidebar';
import { StatusBar } from './components/StatusBar';
import { Dashboard } from './pages/Dashboard';
import { ThreatsPage } from './pages/ThreatsPage';
import { ProcessesPage } from './pages/ProcessesPage';
import { NetworkPage } from './pages/NetworkPage';
import { LogsPage } from './pages/LogsPage';
import { SettingsPage } from './pages/SettingsPage';
import { useState, useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

export function App() {
  const [activeView, setActiveView] = useState(0);

  useEffect(() => {
    // C# pushes activeView updates
    (window as any).setActiveView = (viewId: number) => {
      setActiveView(viewId);
    };
    return () => { delete (window as any).setActiveView; };
  }, []);

  const views = [
    <Dashboard key="dash" />,
    <ThreatsPage key="threats" />,
    <ProcessesPage key="processes" />,
    <NetworkPage key="network" />,
    <LogsPage key="logs" />,
    <SettingsPage key="settings" />,
  ];

  return (
    <div className="h-screen w-screen flex flex-col bg-[var(--bg-deep)] overflow-hidden relative">
      {/* Global background image */}
      <div
        className="absolute inset-0 z-0"
        style={{
          backgroundImage: 'url(./background.png)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          opacity: 0.6
        }} />

      {/* Circuit overlay */}
      <div
        className="absolute inset-0 z-0"
        style={{
          backgroundImage: 'url(./overlay.png)',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          mixBlendMode: 'screen',
          opacity: 0.3
        }} />

      {/* Title bar */}
      <div className="relative z-10">
        <TitleBar />
      </div>

      {/* Main layout */}
      <div className="flex-1 flex overflow-hidden relative z-10">
        <Sidebar activeView={activeView} onNavigate={(id) => {
          setActiveView(id);
          try { (window as any).chrome?.webview?.postMessage(`navigate:${id}`); } catch { }
        }} />

        {/* Page content with transition animation */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeView}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="flex-1 flex flex-col overflow-hidden"
            >
              {views[activeView] || views[0]}
            </motion.div>
          </AnimatePresence>

          {/* StatusBar always visible on all views */}
          <StatusBar />
        </div>
      </div>
    </div>);
}