/**
 * Estado do painel de terminal.
 *
 * Separado do useSentinel porque não tem nada a ver com varredura: são ciclos
 * de vida independentes, e misturar faria uma varredura em andamento
 * re-renderizar os terminais sem motivo.
 */

import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { pty, type Session, type SessionSpec } from "./terminal";

type OpenRequest = SessionSpec & { label?: string };

export function useTerminal() {
  const [available, setAvailable] = useState(false);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Binário compilado sem a feature `terminal` não tem os comandos. Melhor
  // esconder o painel que mostrar botão que devolve erro.
  useEffect(() => {
    invoke<boolean>("terminal_available")
      .then(setAvailable)
      .catch(() => setAvailable(false));
  }, []);

  // Processo que termina não fecha a aba: a pessoa costuma querer ler a última
  // saída (código de erro do ssh, resumo do ping) antes de descartar.
  useEffect(() => {
    const un = pty.onExit((id) => {
      setSessions((ss) => ss.map((s) => (s.id === id ? { ...s, exited: true } : s)));
    });
    return () => { un.then((fn) => fn()); };
  }, []);

  const openSession = useCallback(async (req: OpenRequest) => {
    setError(null);
    const { label, ...spec } = req;
    try {
      const id = await pty.open(spec as SessionSpec, 24, 100);
      setSessions((ss) => [...ss, { id, kind: spec.kind, label }]);
      return id;
    } catch (e) {
      // Falha típica: `ssh` ou `telnet` não instalado. A mensagem do Rust já
      // diz qual comando faltou.
      setError(String(e));
      return null;
    }
  }, []);

  const closeSession = useCallback(async (id: string) => {
    try { await pty.close(id); } catch { /* já pode ter morrido */ }
    setSessions((ss) => ss.filter((s) => s.id !== id));
  }, []);

  return {
    available, sessions, error,
    openSession, closeSession,
    clearError: () => setError(null),
  };
}