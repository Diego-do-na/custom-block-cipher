import type { HTMLAttributes, ReactNode } from 'react';

interface PanelProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

export function Panel({ title, description, icon, actions, children, className = '', ...rest }: PanelProps) {
  return (
    <div
      className={`rounded-xl border border-border bg-card shadow-[0_1px_0_0_rgba(255,255,255,0.03)_inset] ${className}`}
      {...rest}
    >
      {(title || actions) && (
        <div className="flex items-center justify-between gap-4 border-b border-border px-5 py-4">
          <div className="flex items-center gap-3">
            {icon && <span className="text-diffusion">{icon}</span>}
            <div>
              {title && <h3 className="font-display text-sm font-semibold tracking-wide text-foreground uppercase">{title}</h3>}
              {description && <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>}
            </div>
          </div>
          {actions}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}
