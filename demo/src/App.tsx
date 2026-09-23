import { useState } from 'react';
import { IconBook, IconLock, IconLayers, IconZap } from './icons/icons';
import { ExplainerSection } from './components/explainer/ExplainerSection';
import { LiveDemoSection } from './components/live/LiveDemoSection';
import { RoundVisualizerSection } from './components/visualizer/RoundVisualizerSection';
import { AvalancheSection } from './components/avalanche/AvalancheSection';

const TABS = [
  { id: 'explainer', label: 'How It Works', icon: IconBook },
  { id: 'live', label: 'Live Demo', icon: IconLock },
  { id: 'visualizer', label: 'Round Visualizer', icon: IconLayers },
  { id: 'avalanche', label: 'Avalanche Effect', icon: IconZap },
] as const;

type TabId = (typeof TABS)[number]['id'];

function App() {
  const [tab, setTab] = useState<TabId>('explainer');

  return (
    <div className="min-h-dvh bg-background text-foreground">
      <header className="sticky top-0 z-10 border-b border-border bg-background/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div>
            <p className="font-display text-xs font-medium tracking-widest text-diffusion uppercase">
              Confusion &amp; Diffusion
            </p>
            <h1 className="font-display text-xl font-semibold tracking-tight text-foreground">
              Custom Block Cipher — Live Demo
            </h1>
          </div>
          <nav aria-label="Demo sections" className="flex flex-wrap gap-1 rounded-lg bg-panel p-1 ring-1 ring-inset ring-border">
            {TABS.map(({ id, label, icon: Icon }) => {
              const active = tab === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setTab(id)}
                  aria-current={active ? 'page' : undefined}
                  className={`inline-flex min-h-10 cursor-pointer items-center gap-2 rounded-md px-3 py-1.5 font-display text-sm font-medium tracking-wide transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring ${
                    active ? 'bg-diffusion text-diffusion-foreground' : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                  }`}
                >
                  <Icon className="size-4" />
                  {label}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10">
        {tab === 'explainer' && <ExplainerSection />}
        {tab === 'live' && <LiveDemoSection />}
        {tab === 'visualizer' && <RoundVisualizerSection />}
        {tab === 'avalanche' && <AvalancheSection />}
      </main>

      <footer className="mx-auto max-w-6xl px-6 pb-10 text-xs text-muted-foreground">
        <p>
          Educational cipher for a university confusion/diffusion assignment — not a production-grade algorithm.
          See <code className="font-mono text-muted-foreground">SECURITY.md</code> for the full design writeup and known limitations.
        </p>
      </footer>
    </div>
  );
}

export default App;
