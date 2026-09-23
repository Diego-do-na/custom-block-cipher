import type { ReactNode } from 'react';

type BadgeTone = 'secret' | 'public' | 'confusion' | 'diffusion' | 'success' | 'danger' | 'neutral';

const TONE_CLASSES: Record<BadgeTone, string> = {
  secret: 'bg-destructive/15 text-red-300 ring-1 ring-inset ring-destructive/40',
  public: 'bg-accent/15 text-emerald-300 ring-1 ring-inset ring-accent/40',
  confusion: 'bg-confusion/15 text-violet-300 ring-1 ring-inset ring-confusion/40',
  diffusion: 'bg-diffusion/15 text-cyan-300 ring-1 ring-inset ring-diffusion/40',
  success: 'bg-accent/15 text-emerald-300 ring-1 ring-inset ring-accent/40',
  danger: 'bg-destructive/15 text-red-300 ring-1 ring-inset ring-destructive/40',
  neutral: 'bg-muted text-muted-foreground ring-1 ring-inset ring-border',
};

export function Badge({ tone = 'neutral', icon, children }: { tone?: BadgeTone; icon?: ReactNode; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-display text-[11px] font-medium tracking-wide uppercase ${TONE_CLASSES[tone]}`}
    >
      {icon && <span className="[&>svg]:size-3.5">{icon}</span>}
      {children}
    </span>
  );
}
