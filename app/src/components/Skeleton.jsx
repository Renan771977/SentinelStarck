/**
 * Skeletons de carregamento, no estilo do GitHub.
 *
 * Enquanto os dados chegam, mostramos a FORMA do conteúdo — blocos cinza com um
 * brilho que desliza — em vez de um spinner ou tela vazia. Isso comunica "está
 * vindo, e vai ter esta cara", que é menos ansioso que um vazio e mais honesto
 * que um spinner genérico.
 *
 * O shimmer é um gradiente que se move via animação CSS, definida no index.css.
 */

import { T } from "../lib/theme";


/** Bloco base com o brilho deslizante. */
export function SkelBlock({ w = "100%", h = 14, radius = 6, style = {} }) {
  return (
    <span style={{
      display: "block",
      width: w, height: h, borderRadius: radius,
      background: `linear-gradient(90deg, ${T.skelBase} 25%, ${T.skelShine} 50%, ${T.skelBase} 75%)`,
      backgroundSize: "200% 100%",
      animation: "skel-shimmer 1.3s ease-in-out infinite",
      ...style,
    }} />
  );
}

/** Linha de tabela de dispositivos: ícone, nome, IP, colunas. */
export function SkeletonDeviceList({ rows = 8 }) {
  return (
    <div className="rounded-lg overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 px-4 h-14"
          style={{ borderBottom: `1px solid ${T.borderSubtle}`, opacity: 1 - i * 0.06 }}>
          <SkelBlock w={15} h={15} radius={4} />
          <div className="flex-1 flex flex-col gap-1.5">
            <SkelBlock w={140} h={12} />
            <SkelBlock w={80} h={9} />
          </div>
          <SkelBlock w={110} h={12} />
          <SkelBlock w={130} h={12} />
          <SkelBlock w={40} h={12} />
          <SkelBlock w={60} h={18} radius={4} />
        </div>
      ))}
    </div>
  );
}

/** Cartões do dashboard: a faixa superior. */
export function SkeletonDashboard() {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
            <SkelBlock w={90} h={10} />
            <SkelBlock w={60} h={26} radius={6} style={{ marginTop: 12 }} />
            <SkelBlock w={100} h={9} style={{ marginTop: 10 }} />
          </div>
        ))}
      </div>
      <div className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
        <SkelBlock w={180} h={12} />
        <SkelBlock w="100%" h={240} radius={8} style={{ marginTop: 14 }} />
      </div>
    </div>
  );
}

/** Detalhe de dispositivo carregando (portas, achados). */
export function SkeletonList({ rows = 4 }) {
  return (
    <div className="rounded-lg overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 px-4 h-11"
          style={{ borderBottom: `1px solid ${T.borderSubtle}`, opacity: 1 - i * 0.1 }}>
          <SkelBlock w={40} h={12} />
          <SkelBlock w={90} h={12} />
          <SkelBlock w={200} h={12} />
        </div>
      ))}
    </div>
  );
}