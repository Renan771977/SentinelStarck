import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { T, SEVERITY, sans } from "./theme";

/**
 * Diálogos do próprio app: substituem window.prompt e window.confirm.
 *
 * Os diálogos nativos do navegador ("localhost:5173 diz…") quebram a estética e
 * denunciam que é uma página web. Este provider expõe uma API com a mesma
 * ergonomia — `await dialog.prompt(...)` retorna o texto ou null — mas
 * renderizado no tema do app.
 *
 * A API é assíncrona e baseada em promessa: `const nome = await dialog.prompt(...)`
 * lê tão natural quanto o window.prompt, mas sem o visual de navegador.
 */


const DialogContext = createContext(null);

export function useDialog() {
  const ctx = useContext(DialogContext);
  if (!ctx) {
    // Fallback para o nativo, caso não haja provider — a chamada nunca quebra.
    return {
      prompt: async (opts) => window.prompt(opts?.title || "", opts?.initial || ""),
      confirm: async (opts) => window.confirm(opts?.message || ""),
    };
  }
  return ctx;
}

export function DialogProvider({ children }) {
  const [dialog, setDialog] = useState(null);
  const resolver = useRef(null);

  const close = useCallback((value) => {
    resolver.current?.(value);
    resolver.current = null;
    setDialog(null);
  }, []);

  const api = {
    /**
     * Pede um texto. Resolve com a string, ou null se cancelado.
     * opts: { title, label, initial, placeholder, confirmLabel, required, multiline }
     */
    prompt: (opts = {}) =>
      new Promise((resolve) => {
        resolver.current = resolve;
        setDialog({ kind: "prompt", ...opts });
      }),

    /**
     * Pede confirmação. Resolve true/false.
     * opts: { title, message, confirmLabel, danger }
     */
    confirm: (opts = {}) =>
      new Promise((resolve) => {
        resolver.current = resolve;
        setDialog({ kind: "confirm", ...opts });
      }),
  };

  return (
    <DialogContext.Provider value={api}>
      {children}
      {dialog && <DialogView dialog={dialog} onClose={close} />}
    </DialogContext.Provider>
  );
}

function DialogView({ dialog, onClose }) {
  const [value, setValue] = useState(dialog.initial || "");
  const inputRef = useRef(null);
  const isPrompt = dialog.kind === "prompt";

  useEffect(() => {
    // Foca e seleciona o texto ao abrir, como o prompt nativo faz.
    const t = window.setTimeout(() => {
      inputRef.current?.focus();
      inputRef.current?.select?.();
    }, 40);
    return () => window.clearTimeout(t);
  }, []);

  // Enter confirma, Esc cancela — o que a pessoa espera de um diálogo.
  const onKey = (e) => {
    if (e.key === "Enter" && !dialog.multiline) { e.preventDefault(); submit(); }
    if (e.key === "Escape") { e.preventDefault(); onClose(isPrompt ? null : false); }
  };

  const submit = () => {
    if (isPrompt) {
      const v = value.trim();
      if (dialog.required && !v) return; // não fecha sem o obrigatório
      onClose(v || null);
    } else {
      onClose(true);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: T.overlay }}
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(isPrompt ? null : false); }}>
      <div className="rounded-lg" onKeyDown={onKey}
        style={{ background: T.surface, border: `1px solid ${T.border}`, width: 440, boxShadow: T.shadowModal }}>
        <header className="flex items-center justify-between px-4 h-12" style={{ borderBottom: `1px solid ${T.border}` }}>
          <span className="text-sm font-medium" style={{ ...sans, color: T.text }}>
            {dialog.title || (isPrompt ? "Editar" : "Confirmar")}
          </span>
          <button onClick={() => onClose(isPrompt ? null : false)} style={{ color: T.faint }}>
            <X size={15} />
          </button>
        </header>

        <div className="p-4">
          {isPrompt ? (
            <>
              {dialog.label && (
                <label className="text-xs block mb-1.5" style={{ ...sans, color: T.faint }}>{dialog.label}</label>
              )}
              {dialog.multiline ? (
                <textarea ref={inputRef} value={value} onChange={(e) => setValue(e.target.value)}
                  placeholder={dialog.placeholder} rows={3}
                  className="w-full rounded-md px-3 py-2 text-sm outline-none resize-none"
                  style={{ ...sans, background: T.raised, color: T.text, border: `1px solid ${T.border}` }} />
              ) : (
                <input ref={inputRef} value={value} onChange={(e) => setValue(e.target.value)}
                  placeholder={dialog.placeholder}
                  className="w-full rounded-md px-3 h-10 text-sm outline-none"
                  style={{ ...sans, background: T.raised, color: T.text, border: `1px solid ${T.border}` }} />
              )}
            </>
          ) : (
            <p className="text-sm" style={{ ...sans, color: T.dim, maxWidth: "60ch" }}>{dialog.message}</p>
          )}
        </div>

        <footer className="flex justify-end gap-2 px-4 pb-4">
          <button onClick={() => onClose(isPrompt ? null : false)}
            className="rounded-md px-3 h-9 text-sm"
            style={{ ...sans, background: "transparent", color: T.dim, border: `1px solid ${T.border}` }}>
            Cancelar
          </button>
          <button onClick={submit} autoFocus={!isPrompt}
            className="rounded-md px-3.5 h-9 text-sm font-medium"
            style={{
              ...sans,
              background: dialog.danger ? SEVERITY.critical : T.accent,
              color: T.onAccent,
            }}>
            {dialog.confirmLabel || (isPrompt ? "Salvar" : "Confirmar")}
          </button>
        </footer>
      </div>
    </div>
  );
}