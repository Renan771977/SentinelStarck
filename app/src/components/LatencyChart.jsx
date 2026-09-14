import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { T, SEVERITY, resolveColor } from "../lib/theme";
import { useTheme } from "../lib/useTheme";

/**
 * Gráfico de latência ao vivo, em canvas via uPlot.
 *
 * Canvas, não SVG (Recharts): uma série amostrada a cada 2s por 10 minutos são
 * 300 pontos por alvo, e uPlot desenha isso sem custo. Se um dia a janela for
 * de 24h, são dezenas de milhares de pontos — território onde SVG trava e
 * canvas nem sente.
 */
/**
 * Cores das séries, RESOLVIDAS.
 *
 * uPlot pinta em canvas e não aceita `var(--x)`. Função em vez de constante
 * para reler quando o tema mudar — o gráfico é recriado nessa hora.
 */
function seriesColors() {
  return [T.accent, T.accent2, T.ok, SEVERITY.medium, SEVERITY.high].map(resolveColor);
}

export default function LatencyChart({ series, height = 220 }) {
  const { theme } = useTheme();
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
          stroke: resolveColor(T.faint),
          grid: { stroke: resolveColor(T.borderSubtle) },
          ticks: { stroke: resolveColor(T.border) },
          font: "11px Inter, sans-serif",
        },
        {
          stroke: resolveColor(T.faint),
          grid: { stroke: resolveColor(T.borderSubtle) },
          ticks: { stroke: resolveColor(T.border) },
          font: "11px 'JetBrains Mono', monospace",
          size: 52,
          values: (_u, vals) => vals.map((v) => `${v} ms`),
        },
      ],
      series: (() => {
        const colors = seriesColors();
        return [
        {},
        ...series.map((s, i) => ({
          label: s.label,
          stroke: colors[i % colors.length],
          width: 1.6,
          // Ponto perdido (null) vira lacuna, não linha até zero: uma linha
          // caindo a zero mentiria dizendo "latência baixíssima".
          spanGaps: false,
          // Mostra o ponto quando há poucos dados: uma série de 1-2 amostras
          // como linha pura é invisível.
          points: { show: (u) => u.data[0].length < 10, size: 4 },
        })),
      ];
      })(),
    };

    plot.current = new uPlot(opts, toData(series), ref.current);

    const ro = new ResizeObserver(() => {
      plot.current?.setSize({ width: ref.current.clientWidth, height });
    });
    ro.observe(ref.current);

    return () => { ro.disconnect(); plot.current?.destroy(); };
    // Recria só quando o CONJUNTO de séries muda (alvo novo), não a cada ponto.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    // `theme` na dependência: uPlot pinta em canvas com cor resolvida, então
    // trocar de tema exige recriar o gráfico. É barato — algumas centenas de
    // pontos — e acontece só na troca.
  }, [series.map((s) => s.targetId).join(","), height, theme]);

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