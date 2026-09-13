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

type OpenRequest = SessionSpec & {
  label?: string;
  /**
   * Comando a digitar assim que o shell abrir, SEM executar. A pessoa vê o
   * comando pronto na linha e confirma com Enter. Só faz sentido com um shell.
   */
  prefill?: string;
};

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
    const { label, prefill, ...spec } = req;
    try {
      const id = await pty.open(spec as SessionSpec, 24, 100);
      setSessions((ss) => [...ss, { id, kind: spec.kind, label }]);

      // Digita o comando no shell recém-aberto, sem Enter. Um pequeno atraso
      // dá tempo de o shell imprimir o prompt antes; sem ele, o comando
      // apareceria antes do "PS C:\>" e ficaria bagunçado.
      if (prefill) {
        // O prompt do PowerShell inicializado com -Command demora um pouco
        // mais; 600ms evita o comando aparecer antes do "PS C:\>".
        window.setTimeout(() => { pty.write(id, prefill).catch(() => {}); }, 600);
      }
      return id;
    } catch (e) {
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