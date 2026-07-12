import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';
import { cn } from './utils';

export type ToastKind = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
}

interface ToastContextValue {
  toast: (kind: ToastKind, title: string, description?: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const ICONS: Record<ToastKind, typeof Info> = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
};

const COLORS: Record<ToastKind, string> = {
  success: 'text-ok',
  error: 'text-bad',
  warning: 'text-warn',
  info: 'text-accent',
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((cur) => cur.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (kind: ToastKind, title: string, description?: string) => {
      const id = nextId.current++;
      setToasts((cur) => [...cur.slice(-3), { id, kind, title, description }]);
      window.setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 4500);
    },
    [dismiss],
  );

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2"
      >
        {toasts.map((t) => {
          const Icon = ICONS[t.kind];
          return (
            <div
              key={t.id}
              role="status"
              className="vd-slide-in-right pointer-events-auto flex items-start gap-2.5 rounded-lg border border-border bg-surface p-3 shadow-[var(--shadow-md)]"
            >
              <Icon size={17} className={cn('mt-0.5 shrink-0', COLORS[t.kind])} aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-semibold text-text">{t.title}</p>
                {t.description && <p className="mt-0.5 text-xs text-muted">{t.description}</p>}
              </div>
              <button
                type="button"
                aria-label="Dismiss notification"
                onClick={() => dismiss(t.id)}
                className="rounded p-0.5 text-faint hover:bg-surface-2 hover:text-text"
              >
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

/** No-op fallback so components render outside the provider (e.g. in tests). */
const FALLBACK_TOAST: ToastContextValue = { toast: () => undefined };

export function useToast(): ToastContextValue {
  return useContext(ToastContext) ?? FALLBACK_TOAST;
}
