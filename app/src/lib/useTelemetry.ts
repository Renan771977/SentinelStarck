/**
 * Estado da telemetria ao vivo.
 *
 * Consome o evento `telemetry:sample` (emitido a cada 2s pelo laço no Rust) e
 * mantém uma janela deslizante de pontos por alvo, pronta para o gráfico. Ao
 * montar, carrega o histórico recente para o gráfico já abrir preenchido em
 * vez de vazio esperando o primeiro evento.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, type TelemetryPoint } from "./api";

/** Quantos minutos de histórico manter na tela. */
const WINDOW_MIN = 10;
const WINDOW_MS = WINDOW_MIN * 60 * 1000;

export interface Series {
  targetId: number;
  kind: string;
  label: string;
  /** [timestamp_ms, rtt_ms|null][] em ordem cronológica. */
  points: [number, number | null][];
}

export interface TelemetryState {
  series: Series[];
  /** Última leitura de cada alvo, para os cartões numéricos. */
  latest: Record<number, { rtt: number | null; label: string; kind: string }>;
  /** Perda de pacote (%) por alvo na janela. */
  loss: Record<number, number>;
  connected: boolean;
}

export function useTelemetry(): TelemetryState {
  // Guardamos os pontos em ref (mutável, sem re-render) e espelhamos em estado
  // a cada evento. Um evento a cada 2s é leve, então re-render direto é ok.
  const buckets = useRef<Map<number, Series>>(new Map());
  const [tick, setTick] = useState(0);
  const [connected, setConnected] = useState(false);

  const ingest = (pts: TelemetryPoint[]) => {
    const nowMs = Date.now();
    for (const p of pts) {
      let s = buckets.current.get(p.targetId);
      if (!s) {
        s = { targetId: p.targetId, kind: p.kind, label: p.label || p.kind, points: [] };
        buckets.current.set(p.targetId, s);
      }
      s.points.push([p.at * 1000, p.rttMs]);
      // Poda o que saiu da janela.
      const cutoff = nowMs - WINDOW_MS;
      while (s.points.length && s.points[0][0] < cutoff) s.points.shift();
    }
    setTick((t) => t + 1);
  };

  useEffect(() => {
    let alive = true;

    // Histórico primeiro, para o gráfico abrir cheio.
    api.telemetryHistory(WINDOW_MIN).then((hist) => {
      if (!alive) return;
      ingest(hist);
    }).catch(() => {});

    const un = listen<TelemetryPoint[]>("telemetry:sample", (e) => {
      setConnected(true);
      ingest(e.payload);
    });

    return () => { alive = false; un.then((fn) => fn()); };
  }, []);

  return useMemo(() => {
    const series = Array.from(buckets.current.values());
    const latest: TelemetryState["latest"] = {};
    const loss: TelemetryState["loss"] = {};

    for (const s of series) {
      const last = s.points[s.points.length - 1];
      latest[s.targetId] = { rtt: last ? last[1] : null, label: s.label, kind: s.kind };
      const total = s.points.length || 1;
      const lost = s.points.filter((p) => p[1] === null).length;
      loss[s.targetId] = (lost / total) * 100;
    }

    return { series, latest, loss, connected };
    // tick força o recálculo a cada ingest.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, connected]);
}