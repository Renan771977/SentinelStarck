import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { Plus, X, TerminalSquare, Trash2 } from "lucide-react";
import { pty } from "../lib/terminal";
import "@xterm/xterm/css/xterm.css";

const C = {
  panel: "#0F141D", raised: "#161D29", line: "#222C3C", lineSoft: "#19212E",
  text: "#E8ECF4", dim: "#9AA5B8", faint: "#6B7688", cyan: "#00C2FF",
};
const sans = { fontFamily: "Inter,-apple-system,'Segoe UI',sans-serif" };

/** Tema do xterm derivado da paleta do app, não dos padrões da biblioteca. */
const THEME = {
  background: "#0B0F16",
  foreground: "#E8ECF4",
  cursor: "#00C2FF",
  cursorAccent: "#0B0F16",
  selectionBackground: "#00C2FF33",
  black: "#0B0F16", red: "#FF4D6D", green: "#35D07F", yellow: "#FFC94D",
  blue: "#4DA8FF", magenta: "#7C3AED", cyan: "#00C2FF", white: "#C9D1DE",
  brightBlack: "#6B7688", brightRed: "#FF7A90", brightGreen: "#5FE3A1",
  brightYellow: "#FFD97A", brightBlue: "#7CC3FF", brightMagenta: "#A47BF5",
  brightCyan: "#5FD8FF", brightWhite: "#F2F5FA",
};

const KIND_LABEL = {
  shell: "Shell",
  ssh: "SSH",
  telnet: "Telnet",
  ping: "Ping",
  traceroute: "Traceroute",
};

/**
 * Painel inferior com abas de terminal.
 *
 * Cada aba tem uma instância própria do xterm que permanece VIVA quando a aba
 * fica oculta. Destruir e recriar perderia o histórico da sessão, que é
 * justamente o que a pessoa quer consultar ao voltar para a aba.
 */
export default function TerminalPanel({ sessions, onOpen, onClose, visible = true }) {
  const hostRefs = useRef(new Map());   // id -> div
  const terms = useRef(new Map());      // id -> { term, fit, unlisten }
  const [active, setActive] = useState(null);

  useEffect(() => {
    if (sessions.length === 0) {
      setActive(null);
    } else if (!sessions.some((s) => s.id === active)) {
      setActive(sessions[sessions.length - 1].id);
    }
  }, [sessions, active]);

  // Monta o xterm de cada sessão nova e desmonta o das que saíram.
  useEffect(() => {
    for (const s of sessions) {
      if (terms.current.has(s.id)) continue;
      const host = hostRefs.current.get(s.id);
      if (!host) continue;

      const term = new XTerm({
        theme: THEME,
        fontFamily: "'JetBrains Mono','SFMono-Regular',Consolas,monospace",
        fontSize: 13,
        lineHeight: 1.35,
        cursorBlink: true,
        // O histórico do terminal é a memória da investigação: rolar para trás
        // e reler o que o switch respondeu vale mais que economizar memória.
        scrollback: 5000,
        allowProposedApi: true,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(host);
      fit.fit();

      // Teclado -> PTY. Nada é interpretado aqui: o byte vai cru.
      term.onData((data) => pty.write(s.id, data));

      // Redimensionar precisa chegar ao PTY, senão programas de tela cheia
      // (vim, menu de configuração de switch) desenham fora do lugar.
      term.onResize(({ rows, cols }) => pty.resize(s.id, rows, cols));

      const unlisten = pty.onOutput(s.id, (bytes) => term.write(bytes));

      terms.current.set(s.id, { term, fit, unlisten });
      if (s.id === active) term.focus();
    }

    for (const [id, entry] of terms.current) {
      if (sessions.some((s) => s.id === id)) continue;
      entry.unlisten.then((fn) => fn());
      entry.term.dispose();
      terms.current.delete(id);
    }
  }, [sessions, active]);

  // Limpeza ao desmontar o painel inteiro.
  useEffect(() => {
    const registry = terms.current;
    return () => {
      for (const entry of registry.values()) {
        entry.unlisten.then((fn) => fn());
        entry.term.dispose();
      }
      registry.clear();
    };
  }, []);

  // Um ResizeObserver no painel serve todas as abas: só a visível tem
  // dimensão real, e é a única que precisa recalcular.
  const panelRef = useRef(null);
  useEffect(() => {
    const el = panelRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const entry = terms.current.get(active);
      if (entry) {
        try { entry.fit.fit(); } catch { /* painel colapsado */ }
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [active]);

  useEffect(() => {
    if (!visible) return;
    const entry = terms.current.get(active);
    if (!entry) return;
    // Duas passadas: a primeira roda antes de o layout assentar depois do
    // display voltar, e sozinha calcula colunas de menos.
    const apply = () => {
      try { entry.fit.fit(); } catch { /* ainda sem dimensão */ }
    };
    apply();
    const t = window.setTimeout(() => { apply(); entry.term.focus(); }, 30);
    return () => window.clearTimeout(t);
  }, [active, visible]);

  const clear = useCallback(() => {
    terms.current.get(active)?.term.clear();
  }, [active]);

  return (
    <div ref={panelRef} className="flex flex-col h-full min-h-0" style={{ background: C.panel }}>
      <header className="flex items-center gap-1 h-9 px-2 shrink-0"
        style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
        <TerminalSquare size={14} style={{ color: C.faint }} className="mx-1 shrink-0" />

        <div className="flex items-center gap-1 flex-1 min-w-0 overflow-x-auto">
          {sessions.map((s) => (
            <button key={s.id} onClick={() => setActive(s.id)}
              className="group flex items-center gap-1.5 h-7 pl-2.5 pr-1.5 rounded text-xs shrink-0"
              style={{
                ...sans,
                background: active === s.id ? C.raised : "transparent",
                color: active === s.id ? C.text : C.faint,
                border: `1px solid ${active === s.id ? C.line : "transparent"}`,
              }}>
              <span style={{ color: active === s.id ? C.cyan : C.faint }}>
                {KIND_LABEL[s.kind] || s.kind}
              </span>
              {s.label && <span className="truncate" style={{ maxWidth: 140 }}>{s.label}</span>}
              {s.exited && <span style={{ color: C.faint }}>·encerrado</span>}
              {/* Encerrar mata o processo e descarta o histórico. Fica
                  sempre visível na aba ativa: escondido atrás de hover, numa
                  aba só, o botão some e a pessoa não acha como fechar. */}
              <span onClick={(e) => { e.stopPropagation(); onClose(s.id); }}
                className="rounded p-0.5 group-hover:opacity-100"
                style={{ color: C.faint, opacity: active === s.id ? 0.7 : 0 }}
                title="Encerrar sessão">
                <X size={11} />
              </span>
            </button>
          ))}

          <button onClick={() => onOpen({ kind: "shell" })}
            className="flex items-center justify-center rounded shrink-0"
            style={{ width: 26, height: 26, color: C.faint }} title="Novo shell local">
            <Plus size={14} />
          </button>
        </div>

        <button onClick={clear} disabled={!active}
          className="flex items-center justify-center rounded shrink-0"
          style={{ width: 26, height: 26, color: C.faint, opacity: active ? 1 : 0.4 }}
          title="Limpar">
          <Trash2 size={13} />
        </button>
      </header>

      <div className="flex-1 min-h-0 relative">
        {sessions.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2">
            <p className="text-sm" style={{ ...sans, color: C.dim }}>Nenhuma sessão aberta</p>
            <p className="text-xs text-center" style={{ ...sans, color: C.faint, maxWidth: 380 }}>
              Abra um shell local pelo botão acima, ou vá ao detalhe de um dispositivo
              para conectar nele conforme os serviços que a varredura encontrou.
            </p>
          </div>
        )}

        {sessions.map((s) => (
          <div key={s.id}
            ref={(el) => { if (el) hostRefs.current.set(s.id, el); else hostRefs.current.delete(s.id); }}
            className="absolute inset-0 px-2 py-1"
            // Aba oculta continua montada: destruir perderia o histórico da
            // sessão, que é o que a pessoa volta para reler.
            style={{ visibility: active === s.id ? "visible" : "hidden" }}
          />
        ))}
      </div>
    </div>
  );
}

/**
 * Botões de ação para o detalhe do dispositivo.
 *
 * Oferece só o que a varredura realmente encontrou. Mostrar SSH num host sem
 * a porta 22 aberta é convidar o usuário a esperar um timeout.
 */
export function DeviceTerminalActions({ ip, label, services, onOpen }) {
  if (!ip) return null;

  const has = (p) => services?.some((s) => s.port === p && s.protocol === "tcp");
  const specs = [];

  if (has(22)) specs.push({ kind: "ssh", host: ip, label: label || ip, title: "Conectar por SSH" });
  if (has(23)) {
    specs.push({
      kind: "telnet", host: ip, label: label || ip,
      title: "Conectar por Telnet — a senha trafega em texto claro",
      warn: true,
    });
  }
  specs.push({ kind: "ping", host: ip, label: label || ip, title: "Ping contínuo" });
  specs.push({ kind: "traceroute", host: ip, label: label || ip, title: "Traçar rota" });

  return (
    <div className="flex flex-wrap gap-2">
      {specs.map((s) => (
        <button key={s.kind} onClick={() => onOpen(s)} title={s.title}
          className="inline-flex items-center gap-1.5 rounded-md px-2.5 h-8 text-sm"
          style={{
            ...sans,
            background: C.raised,
            color: s.warn ? "#FFC94D" : C.dim,
            border: `1px solid ${s.warn ? "#FFC94D44" : C.line}`,
          }}>
          <TerminalSquare size={13} />
          {KIND_LABEL[s.kind]}
        </button>
      ))}
    </div>
  );
}