/**
 * Ponte para as sessões de terminal.
 *
 * O frontend manda INTENÇÃO, não comando. Quem monta o `argv` é o Rust, com
 * cada argumento separado e sem shell no meio, então não existe injeção
 * possível a partir daqui.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type SessionSpec =
  | { kind: "shell" }
  | { kind: "ssh"; host: string; user?: string; port?: number }
  | { kind: "telnet"; host: string; port?: number }
  | { kind: "ping"; host: string }
  | { kind: "traceroute"; host: string };

export interface Session {
  id: string;
  kind: SessionSpec["kind"];
  label?: string;
  exited?: boolean;
}

export const pty = {
  open: (spec: SessionSpec, rows = 24, cols = 80) =>
    invoke<string>("pty_open", { spec, rows, cols }),

  write: (id: string, data: string) => invoke<void>("pty_write", { id, data }),

  resize: (id: string, rows: number, cols: number) =>
    invoke<void>("pty_resize", { id, rows, cols }),

  close: (id: string) => invoke<void>("pty_close", { id }),

  /**
   * Saída de uma sessão. Chega em base64 porque a leitura do PTY corta em
   * pedaços arbitrários e um caractere UTF-8 pode ficar partido entre duas
   * leituras — converter no Rust transformaria acentos em lixo.
   */
  onOutput: (id: string, cb: (bytes: Uint8Array) => void): Promise<UnlistenFn> =>
    listen<{ id: string; data: string }>("pty:output", (e) => {
      if (e.payload.id !== id) return;
      const raw = atob(e.payload.data);
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      cb(bytes);
    }),

  onExit: (cb: (id: string, code: number) => void): Promise<UnlistenFn> =>
    listen<{ id: string; code: number }>("pty:exit", (e) =>
      cb(e.payload.id, e.payload.code),
    ),
};