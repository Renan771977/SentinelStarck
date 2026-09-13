import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";

/**
 * Gráfico de latência ao vivo, em canvas via uPlot.
 *
 * Canvas, não SVG (Recharts): uma série amostrada a cada 2s por 10 minutos são
 * 300 pontos por alvo, e uPlot desenha isso sem custo. Se um dia a janela for
 * de 24h, são dezenas de milhares de pontos — território onde SVG trava e
 * canvas nem sente.
 */
const COLORS = ["#00C2FF", "#7C3AED", "#35D07F", "#FFC94D", "#FF8A3D"];

export default function LatencyChart({ series, height = 220 }) {
  const ref = useRef(null);
  const plot = useRef(null);

  useEffect(() => {
    if (!ref.current) return;
    // Largura pode ser 0 no primeiro render (layout ainda assentando). Criar o
    // uPlot com width 0 o deixa invisível para sempre; adiamos com um fallback
    // e o ResizeObserver corrige quando o container ganha tamanho.
    const w0 = ref.current.clientWidth || 600;

    const opts = {
      width: w0,
      height,
      cursor: { y: false },
      legend: { show: true },
      scales: {
        x: { time: true },
        // range mínimo: sem isso, dados só de perda (tudo null) deixam o eixo Y
        // colapsado e nada é desenhado.
        y: { auto: true, range: (_u, min, max) => [Math.max(0, (min ?? 0)), Math.max(max ?? 50, 10)] },
      },
      axes: [
        {
          stroke: "#6B7688",
          grid: { stroke: "#19212E" },
          ticks: { stroke: "#222C3C" },
          font: "11px Inter, sans-serif",
        },
        {
          stroke: "#6B7688",
          grid: { stroke: "#19212E" },
          ticks: { stroke: "#222C3C" },
          font: "11px 'JetBrains Mono', monospace",
          size: 52,
          values: (_u, vals) => vals.map((v) => `${v} ms`),
        },
      ],
      series: [
        {},
        ...series.map((s, i) => ({
          label: s.label,
          stroke: COLORS[i % COLORS.length],
          width: 1.6,
          // Ponto perdido (null) vira lacuna, não linha até zero: uma linha
          // caindo a zero mentiria dizendo "latência baixíssima".
          spanGaps: false,
          // Mostra o ponto quando há poucos dados: uma série de 1-2 amostras
          // como linha pura é invisível.
          points: { show: (u) => u.data[0].length < 10, size: 4 },
        })),
      ],
    };

    plot.current = new uPlot(opts, toData(series), ref.current);

    const ro = new ResizeObserver(() => {
      plot.current?.setSize({ width: ref.current.clientWidth, height });
    });
    ro.observe(ref.current);

    return () => { ro.disconnect(); plot.current?.destroy(); };
    // Recria só quando o CONJUNTO de séries muda (alvo novo), não a cada ponto.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [series.map((s) => s.targetId).join(","), height]);

  // Atualização de dados sem recriar o gráfico: barato e fluido.
  useEffect(() => {
    plot.current?.setData(toData(series));
  }, [series]);

  return <div ref={ref} style={{ width: "100%" }} />;
}

/** Converte as séries no formato de uPlot: [tempos[], serie1[], serie2[]...]. */
function toData(series) {
  // uPlot exige um eixo X compartilhado. Unimos todos os timestamps.
  const allX = new Set();
  for (const s of series) for (const [x] of s.points) allX.add(Math.floor(x / 1000));
  const xs = Array.from(allX).sort((a, b) => a - b);

  const cols = [xs];
  for (const s of series) {
    const byT = new Map(s.points.map(([x, y]) => [Math.floor(x / 1000), y]));
    cols.push(xs.map((t) => (byT.has(t) ? byT.get(t) : null)));
  }
  return cols;
}