import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { Check, AlertTriangle, Info, X } from "lucide-react";
import { T, SEVERITY, sans } from "./theme";

/**
 * Toasts: confirmação discreta de ações e avisos de erro.
 *
 * Uma ação que acontece em silêncio (aceitar risco, renomear, exportar) parece
 * que não funcionou. Um toast breve — "risco aceito" — confirma que sim. E
 * quando algo falha, o mesmo canal diz o que falhou, em vez de o erro sumir
 * num `.catch` vazio. É o que dá ao app a sensação de responder.
 */


const KIND = {
  success: { color: T.ok, icon: Check },
  error: { color: SEVERITY.critical, icon: AlertTriangle },
  info: { color: T.accent, icon: Info },
};

const ToastContext = createContext(null);

/** Dispara toasts de qualquer componente: const toast = useToast(). */
export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    // Fallback silencioso: se por algum motivo não houver provider, não
    // quebra a chamada — só não mostra nada.
    return { show: () => {}, success: () => {}, error: () => {}, info: () => {} };
  }
  return ctx;
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const idRef = useRef(0);

  const remove = useCallback((id) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
  }, []);

  const show = useCallback((message, kind = "info", ttl = 3200) => {
    const id = ++idRef.current;
    setToasts((ts) => [...ts, { id, message, kind }]);
    if (ttl > 0) window.setTimeout(() => remove(id), ttl);
    return id;
  }, [remove]);

  const api = {
    show,
    success: (m) => show(m, "success"),
    // Erro fica mais tempo na tela: a pessoa precisa ler o que falhou.
    error: (m) => show(m, "error", 5000),
    info: (m) => show(m, "info"),
  };

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="fixed z-50 flex flex-col gap-2"
        style={{ right: 16, bottom: 16, width: 340, pointerEvents: "none" }}>
        {toasts.map((t) => <Toast key={t.id} toast={t} onClose={() => remove(t.id)} />)}
      </div>
    </ToastContext.Provider>
  );
}

function Toast({ toast, onClose }) {
  const { color, icon: Icon } = KIND[toast.kind] || KIND.info;
  const [entered, setEntered] = useState(false);
  useEffect(() => { requestAnimationFrame(() => setEntered(true)); }, []);

  return (
    <div className="rounded-lg px-3 py-2.5 flex items-start gap-2.5"
      style={{
        background: T.surface, border: `1px solid ${color}44`,
        boxShadow: T.shadowToast, pointerEvents: "auto",
        transform: entered ? "translateX(0)" : "translateX(20px)",
        opacity: entered ? 1 : 0,
        transition: "transform .18s ease, opacity .18s ease",
      }}>
      <Icon size={15} style={{ color, marginTop: 1 }} className="shrink-0" />
      <span className="text-sm flex-1" style={{ ...sans, color: T.text }}>{toast.message}</span>
      <button onClick={onClose} className="shrink-0" style={{ color: T.faint }}>
        <X size={13} />
      </button>
    </div>
  );
}