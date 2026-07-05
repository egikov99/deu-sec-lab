import { ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'secondary' | 'ghost';
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', ...props }, ref) => {
    const variants = {
      default: 'bg-cyan-500 text-white hover:bg-cyan-400',
      secondary: 'bg-slate-800 text-slate-100 hover:bg-slate-700',
      ghost: 'bg-transparent text-slate-300 hover:text-white hover:bg-slate-800',
    };

    return (
      <button
        ref={ref}
        className={cn('rounded-lg px-4 py-2 text-sm font-medium transition', variants[variant], className)}
        {...props}
      />
    );
  },
);

Button.displayName = 'Button';

export { Button };
