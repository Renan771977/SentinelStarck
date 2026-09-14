import { Radar } from "lucide-react";
import { T, sans } from "../lib/theme";


const PHASE_LABEL = {
  discovery: "Procurando dispositivos",
  resolution: "Identificando",
  ports: "Verificando serviços",
  rules: "Avaliando riscos",
  diffing: "Comparando com a última varredura",
};

const PHASE_ORDER = ["discovery", "resolution", "ports", "rules", "diffing"];

/**
 * Estado grande de varredura em andamento, para o Dashboard quando ainda não
 * há dispositivos na lista.
 *
 * Mostra a fase atual e as etapas, para a varredura não ser uma caixa preta.
 * Deixa a pessoa acompanhar em vez de bloquear a tela — quando os dispositivos
 * começam a chegar, o Dashboard troca este componente pelo painel ao vivo.
 */
export default function ScanningState({ phase, percent, found = 0 }) {
  const currentIdx = PHASE_ORDER.indexOf(phase);

  return (
    <div className="rounded-lg" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      <div className="flex flex-col items-center justify-center gap-4 py-16 px-6">
        <div className="relative flex items-center justify-center" style={{ width: 56, height: 56 }}>
          <Radar size={30} style={{ color: T.accent }} className="animate-spin" />
          <div className="absolute inset-0 rounded-full" style={{
            border: `2px solid ${T.accent}22`, borderTopColor: T.accent,
            animation: "spin 1.4s linear infinite",
          }} />
        </div>

        <div className="text-center">
          <p className="text-sm font-medium" style={{ ...sans, color: T.text }}>
            {PHASE_LABEL[phase] || "Varrendo a rede"}
          </p>
          <p className="text-xs mt-1" style={{ ...sans, color: T.faint }}>
            {found > 0
              ? `${found} dispositivo${found > 1 ? "s" : ""} encontrado${found > 1 ? "s" : ""} até agora`
              : "A rede vai aparecer conforme os dispositivos respondem"}
          </p>
        </div>

        {/* Etapas: mostra o progresso pelas fases, não só uma porcentagem. */}
        <div className="flex items-center gap-1.5" style={{ maxWidth: 420 }}>
          {PHASE_ORDER.map((p, i) => {
            const done = i < currentIdx;
            const active = i === currentIdx;
            return (
              <div key={p} className="flex items-center gap-1.5">
                <div className="rounded-full transition-all" style={{
                  width: active ? 8 : 6, height: active ? 8 : 6,
                  background: done ? T.accent : active ? T.accent : T.border,
                  boxShadow: active ? `0 0 8px ${T.accent}` : "none",
                }} />
                {i < PHASE_ORDER.length - 1 && (
                  <div style={{ width: 24, height: 2, background: done ? T.accent : T.borderSubtle }} />
                )}
              </div>
            );
          })}
        </div>

        <div className="w-full" style={{ maxWidth: 360 }}>
          <div className="h-1 rounded-full overflow-hidden" style={{ background: T.raised }}>
            <div className="h-full rounded-full transition-all" style={{
              width: `${percent}%`, background: T.accent,
            }} />
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Barra fina persistente, mostrada no topo do conteúdo em QUALQUER tela
 * enquanto a varredura roda. Assim a varredura nunca é uma caixa preta, mesmo
 * se a pessoa navegar para o Mapa ou Configurações no meio.
 */
export function ScanBanner({ phase, percent }) {
  return (
    <div className="flex items-center gap-3 rounded-lg px-4 h-11 mb-4"
      style={{ background: `${T.accent}0E`, border: `1px solid ${T.accent}33` }}>
      <Radar size={14} style={{ color: T.accent }} className="animate-spin shrink-0" />
      <span className="text-sm" style={{ ...sans, color: T.text }}>
        {PHASE_LABEL[phase] || "Varrendo a rede"}
      </span>
      <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: T.raised }}>
        <div className="h-full rounded-full" style={{ width: `${percent}%`, background: T.accent, transition: "width .3s linear" }} />
      </div>
      <span className="text-xs shrink-0" style={{ ...sans, color: T.dim, fontVariantNumeric: "tabular-nums" }}>
        {percent}%
      </span>
    </div>
  );
}