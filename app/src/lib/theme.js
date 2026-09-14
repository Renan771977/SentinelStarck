/**
 * Ponte entre os tokens CSS e o JavaScript.
 *
 * Os componentes usam cor em `style` inline (herança do protótipo). Em vez de
 * cada um ter sua cópia da paleta, eles importam daqui — e o valor não é a cor,
 * é uma referência à variável CSS.
 *
 * `var(--surface)` funciona em style inline exatamente como em CSS, então o
 * componente continua escrevendo `style={{ background: T.surface }}` e a troca
 * de tema acontece sozinha, sem re-render: o navegador reavalia a variável.
 *
 * Essa é a razão de não usarmos um contexto React com objeto de cores: com
 * variável CSS, trocar tema é mudar um atributo no <html>, e TODO o app muda
 * junto — inclusive canvas e SVG. Um contexto exigiria re-render de tudo.
 */

/** Tokens de cor e superfície. */
export const T = {
  bg: "var(--bg)",
  surface: "var(--surface)",
  raised: "var(--surface-raised)",
  hover: "var(--surface-hover)",
  terminal: "var(--surface-terminal)",

  border: "var(--border)",
  borderSubtle: "var(--border-subtle)",

  text: "var(--text)",
  dim: "var(--text-dim)",
  faint: "var(--text-faint)",
  onAccent: "var(--text-on-accent)",

  accent: "var(--accent)",
  accentSoft: "var(--accent-soft)",
  accentBorder: "var(--accent-border)",
  accent2: "var(--accent-2)",
  accent2Soft: "var(--accent-2-soft)",

  ok: "var(--ok)",
  okSoft: "var(--ok-soft)",

  overlay: "var(--overlay)",
  shadowModal: "var(--shadow-modal)",
  shadowToast: "var(--shadow-toast)",

  skelBase: "var(--skel-base)",
  skelShine: "var(--skel-shine)",
};

/** Severidade por nome. A ordem do array espelha `worstSeverityRank` do Rust. */
export const SEVERITY = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export const SEVERITY_SOFT = {
  critical: "var(--sev-critical-soft)",
  high: "var(--sev-high-soft)",
  medium: "var(--sev-medium-soft)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

/** Índice → nome. O backend manda `worstSeverityRank` como número. */
export const SEVERITY_BY_RANK = ["critical", "high", "medium", "low", "info"];

/** Rótulo em português, para não repetir o mapa em cada componente. */
export const SEVERITY_LABEL = {
  critical: "Crítica",
  high: "Alta",
  medium: "Média",
  low: "Baixa",
  info: "Info",
};

/** Cor de severidade a partir do rank numérico, tolerando null. */
export function severityColorByRank(rank) {
  if (rank === null || rank === undefined) return null;
  return SEVERITY[SEVERITY_BY_RANK[rank]] || SEVERITY.info;
}

/** Fontes. Mantidas como objeto de estilo, como os componentes já usam. */
export const sans = { fontFamily: "var(--font-sans)" };
export const mono = { fontFamily: "var(--font-mono)" };

/** Tokens de movimento, para animação consistente e desligável. */
export const MOTION = {
  fast: "var(--dur-fast)",
  base: "var(--dur-base)",
  slow: "var(--dur-slow)",
  ease: "var(--ease)",
};

/**
 * Cor RESOLVIDA de uma variável, para quem não aceita `var()`.
 *
 * Canvas (uPlot) e algumas APIs precisam de cor literal — `var(--accent)` não
 * funciona lá. Esta função lê o valor computado do documento.
 *
 * Use apenas quando necessário, e releia depois de trocar de tema: o valor é
 * um retrato do momento, não uma referência viva.
 */
export function resolveColor(cssVar) {
  const name = cssVar.replace(/^var\(|\)$/g, "");
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888888";
}