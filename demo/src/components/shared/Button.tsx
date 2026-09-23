import type { ButtonHTMLAttributes, ReactNode } from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'ghost';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  icon?: ReactNode;
  children: ReactNode;
}

const VARIANT_CLASSES: Record<ButtonVariant, string> = {
  primary: 'bg-diffusion text-diffusion-foreground hover:bg-diffusion/90 focus-visible:outline-diffusion',
  secondary: 'bg-panel text-foreground ring-1 ring-inset ring-border hover:bg-muted',
  ghost: 'text-muted-foreground hover:bg-muted hover:text-foreground',
};

export function Button({ variant = 'primary', icon, children, className = '', disabled, ...rest }: ButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      className={`inline-flex min-h-11 cursor-pointer items-center justify-center gap-2 rounded-lg px-4 py-2 font-display text-sm font-medium tracking-wide transition-colors duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-40 ${VARIANT_CLASSES[variant]} ${className}`}
      {...rest}
    >
      {icon && <span className="[&>svg]:size-4">{icon}</span>}
      {children}
    </button>
  );
}
