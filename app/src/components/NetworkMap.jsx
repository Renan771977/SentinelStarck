import { useMemo, useRef, useState } from "react";
import {
  Router, Cable, Server, Monitor, Printer, Camera, HardDrive, Wifi,
  CircleHelp, Smartphone, ShieldAlert, Globe, Search, ZoomIn, ZoomOut,
  Maximize2, Clock, Fingerprint, AlertTriangle,
} from "lucide-react";
import { T, SEVERITY, SEVERITY_BY_RANK, sans, mono } from "../lib/theme";

/* ------------------------------------------------------------------ */
/*  Tokens                                                             */
/* ------------------------------------------------------------------ */

const ICON = {
  router: Router, switch: Cable, firewall: Cable, server: Server,
  workstation: Monitor, printer: Printer, camera: Camera, nas: HardDrive,
  ap: Wifi, phone: Smartphone, iot: CircleHelp, unknown: CircleHelp,
};
const KIND_LABEL = {
  router: "Roteador", switch: "Switch", firewall: "Firewall", server: "Servidor",
  workstation: "Estação", printer: "Impressora", camera: "Câmera", nas: "Storage",
  ap: "Access point", phone: "Celular", iot: "IoT", unknown: "Desconhecido",
};

/**
 * Faixas horizontais do mapa.
 *
 * Agrupar por função, não por ordem alfabética ou por IP: numa investigação a
 * primeira pergunta é "o que é infraestrutura e o que é ponta", e isso precisa
 * saltar aos olhos sem ler um rótulo sequer.
 */
const BANDS = [
  { id: "infra", label: "Infraestrutura", kinds: ["switch", "firewall", "ap"] },
  { id: "servers", label: "Servidores e storage", kinds: ["server", "nas"] },
  { id: "endpoints", label: "Estações e celulares", kinds: ["workstation", "phone"] },
  { id: "periph", label: "Periféricos e IoT", kinds: ["printer", "camera", "iot"] },
  { id: "unknown", label: "Não identificados", kinds: ["unknown"] },
];

/* ------------------------------------------------------------------ */
/*  Sinais de investigação                                             */
/* ------------------------------------------------------------------ */

/**
 * Bit "local administrado" no primeiro octeto.
 *
 * Indica MAC randomizado: celular e notebook modernos trocam de MAC por rede.
 * Num inventário é ruído; numa investigação é sinal, porque também é o que um
 * dispositivo usa para não ser reconhecido entre visitas.
 */
function isRandomizedMac(mac) {
  if (!mac) return false;
  const first = parseInt(mac.replace(/[^0-9a-f]/gi, "").slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) !== 0;
}

function isOffHours(epoch) {
  if (!epoch) return false;
  const h = new Date(epoch * 1000).getHours();
  const d = new Date(epoch * 1000).getDay();
  return h < 7 || h >= 20 || d === 0 || d === 6;
}

/** Marcas que merecem atenção. Ordem = prioridade de exibição. */
function signalsOf(d, now) {
  const out = [];
  if (d.firstSeen && now - d.firstSeen < 86400) out.push({ id: "novo", label: "Novo nas últimas 24h", color: T.accent2 });
  if (isOffHours(d.firstSeen)) out.push({ id: "fora", label: "Apareceu fora do expediente", color: SEVERITY.medium });
  if (isRandomizedMac(d.mac)) out.push({ id: "mac", label: "MAC randomizado", color: SEVERITY.high });
  if (d.identityConfidence === "low") out.push({ id: "conf", label: "Identidade de baixa confiança", color: SEVERITY.high });
  if ((d.ipHistoryCount || 0) > 2) out.push({ id: "ips", label: `Já usou ${d.ipHistoryCount} endereços`, color: SEVERITY.low });
  if (d.missCount > 0) out.push({ id: "off", label: "Ausente na última varredura", color: T.faint });
  return out;
}

const fmt = (e) =>
  e ? new Date(e * 1000).toLocaleString("pt-BR", {
    day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit",
  }) : "—";

/* ------------------------------------------------------------------ */
/*  Geometria                                                          */
/* ------------------------------------------------------------------ */
const CELL_W = 132;
const CELL_H = 100;
const MARGIN_X = 130;
const BAND_HEADER = 34;
const TOP_INTERNET = 46;
const TOP_GATEWAY = 132;
const BUS_Y = 212;
const FIRST_BAND = 268;
const WIDTH = 1240;

function layout(devices, gateway, now) {
  const cols = Math.max(3, Math.floor((WIDTH - MARGIN_X - 40) / CELL_W));
  const bands = [];
  let y = FIRST_BAND;

  for (const band of BANDS) {
    const items = devices.filter((d) => band.kinds.includes(d.kind) && d.id !== gateway?.id);
    if (items.length === 0) continue;

    const rows = Math.ceil(items.length / cols);
    const nodes = items.map((d, i) => ({
      d,
      x: MARGIN_X + (i % cols) * CELL_W + CELL_W / 2,
      y: y + BAND_HEADER + Math.floor(i / cols) * CELL_H + 30,
      signals: signalsOf(d, now),
    }));

    bands.push({ ...band, y, height: BAND_HEADER + rows * CELL_H, nodes, count: items.length });
    y += BAND_HEADER + rows * CELL_H + 14;
  }

  return { bands, height: y + 20 };
}

/* ------------------------------------------------------------------ */
/*  Nó                                                                 */
/* ------------------------------------------------------------------ */
function Node({ node, size = 21, selected, dimmed, onSelect }) {
  const { d, x, y, signals } = node;
  const Icon = ICON[d.kind] || CircleHelp;
  const sev = d.worstSeverityRank !== null && d.worstSeverityRank !== undefined
    ? SEVERITY[SEVERITY_BY_RANK[d.worstSeverityRank]] : null;
  const offline = d.missCount > 0;
  const lowConf = d.identityConfidence === "low";

  const ring = sev || (selected ? T.accent : T.border);

  return (
    <g onClick={() => onSelect(d)} style={{ cursor: "pointer", opacity: dimmed ? 0.18 : 1 }}>
      {selected && (
        <circle cx={x} cy={y} r={size + 7} fill="none" stroke={T.accent} strokeWidth="1" opacity="0.5" />
      )}
      <circle
        cx={x} cy={y} r={size}
        fill={offline ? "var(--surface-offline)" : T.raised}
        stroke={ring}
        strokeWidth={sev ? 2.2 : 1.4}
        // Traço interrompido quando a identidade é fraca. A forma carrega a
        // informação junto com a cor: quem não distingue vermelho de laranja
        // continua vendo que aquele nó é diferente.
        strokeDasharray={lowConf ? "3 3" : undefined}
      />
      <g transform={`translate(${x - 9}, ${y - 9})`} style={{ color: offline ? T.faint : T.dim }}>
        <Icon size={18} />
      </g>

      {/* IP COMPLETO, sempre. Endereço abreviado é inútil em investigação:
          o número inteiro é o que vai para o relatório e para o log. */}
      <text x={x} y={y + size + 15} textAnchor="middle"
        style={{ ...mono, fontSize: 11, fill: offline ? T.faint : T.text }}>
        {d.ip || "sem IP"}
      </text>
      <text x={x} y={y + size + 28} textAnchor="middle"
        style={{ ...sans, fontSize: 10, fill: T.faint }}>
        {(d.label || d.hostname || d.vendor || KIND_LABEL[d.kind] || "").slice(0, 18)}
      </text>

      {/* Marcas de investigação, empilhadas na borda superior direita. */}
      {signals.slice(0, 3).map((s, i) => (
        <circle key={s.id} cx={x + size - 3 - i * 8} cy={y - size + 3} r="3.5"
          fill={s.color} stroke={T.bg} strokeWidth="1">
          <title>{s.label}</title>
        </circle>
      ))}
    </g>
  );
}

/* ------------------------------------------------------------------ */
/*  Mapa                                                               */
/* ------------------------------------------------------------------ */
export default function NetworkMap({ devices, cidr, onOpen }) {
  const now = Math.floor(Date.now() / 1000);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all");
  const [sinceHours, setSinceHours] = useState(0); // 0 = tudo
  const [selected, setSelected] = useState(null);
  const drag = useRef(null);

  const gateway = useMemo(
    () => devices.find((d) => d.kind === "router") || null,
    [devices],
  );

  const visible = useMemo(() => {
    return devices.filter((d) => {
      if (sinceHours > 0 && (!d.firstSeen || now - d.firstSeen > sinceHours * 3600)) return false;
      if (filter === "risk" && (d.worstSeverityRank === null || d.worstSeverityRank > 2)) return false;
      if (filter === "unknown" && d.kind !== "unknown" && d.identityConfidence !== "low") return false;
      if (filter === "offline" && d.missCount === 0) return false;
      return true;
    });
  }, [devices, filter, sinceHours, now]);

  const { bands, height } = useMemo(
    () => layout(visible, gateway, now),
    [visible, gateway, now],
  );

  const matches = (d) => {
    if (!q) return true;
    const hay = `${d.ip || ""} ${d.mac || ""} ${d.label || ""} ${d.hostname || ""} ${d.vendor || ""}`;
    return hay.toLowerCase().includes(q.toLowerCase());
  };

  const onWheel = (e) => {
    e.preventDefault();
    setZoom((z) => Math.min(2.5, Math.max(0.35, z - e.deltaY * 0.0012)));
  };
  const onDown = (e) => { drag.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }; };
  const onMove = (e) => {
    if (!drag.current) return;
    setPan({ x: e.clientX - drag.current.x, y: e.clientY - drag.current.y });
  };
  const stop = () => { drag.current = null; };
  const reset = () => { setZoom(1); setPan({ x: 0, y: 0 }); };

  const gwSignals = gateway ? signalsOf(gateway, now) : [];

  return (
    <div className="flex flex-col h-full min-h-0 gap-3">
      {/* ---- controles ---- */}
      <div className="flex items-center gap-3 flex-wrap shrink-0">
        <div className="flex items-center gap-2 rounded-md px-3 h-9"
          style={{ background: T.surface, border: `1px solid ${T.border}`, minWidth: 260 }}>
          <Search size={14} style={{ color: T.faint }} />
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="Destacar por IP, MAC, nome ou fabricante"
            className="bg-transparent outline-none flex-1 text-sm"
            style={{ ...sans, color: T.text }} />
        </div>

        <div className="flex gap-1 rounded-md p-1" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
          {[
            ["all", "Todos"],
            ["risk", "Com risco"],
            ["unknown", "Não identificados"],
            ["offline", "Ausentes"],
          ].map(([id, lbl]) => (
            <button key={id} onClick={() => setFilter(id)} className="px-2.5 h-7 rounded text-xs"
              style={{ ...sans, background: filter === id ? T.raised : "transparent", color: filter === id ? T.text : T.faint }}>
              {lbl}
            </button>
          ))}
        </div>

        {/* Linha do tempo. "Quem entrou na rede desde então" é a pergunta
            que abre quase toda investigação de incidente. */}
        <div className="flex items-center gap-2 rounded-md px-3 h-9"
          style={{ background: T.surface, border: `1px solid ${T.border}` }}>
          <Clock size={13} style={{ color: T.faint }} />
          <select value={sinceHours} onChange={(e) => setSinceHours(Number(e.target.value))}
            className="bg-transparent outline-none text-sm" style={{ ...sans, color: T.text }}>
            <option value={0} style={{ background: T.surface }}>Todo o histórico</option>
            <option value={1} style={{ background: T.surface }}>Novos na última hora</option>
            <option value={24} style={{ background: T.surface }}>Novos em 24 horas</option>
            <option value={168} style={{ background: T.surface }}>Novos em 7 dias</option>
          </select>
        </div>

        <div className="flex items-center gap-1 ml-auto">
          <button onClick={() => setZoom((z) => Math.max(0.35, z - 0.2))}
            className="rounded-md flex items-center justify-center"
            style={{ width: 30, height: 30, background: T.surface, border: `1px solid ${T.border}`, color: T.dim }}>
            <ZoomOut size={14} />
          </button>
          <button onClick={() => setZoom((z) => Math.min(2.5, z + 0.2))}
            className="rounded-md flex items-center justify-center"
            style={{ width: 30, height: 30, background: T.surface, border: `1px solid ${T.border}`, color: T.dim }}>
            <ZoomIn size={14} />
          </button>
          <button onClick={reset} className="rounded-md flex items-center justify-center"
            style={{ width: 30, height: 30, background: T.surface, border: `1px solid ${T.border}`, color: T.dim }}
            title="Enquadrar">
            <Maximize2 size={13} />
          </button>
        </div>
      </div>

      {/* ---- tela ---- */}
      <div className="flex-1 min-h-0 rounded-lg overflow-hidden relative"
        style={{ background: T.bg, border: `1px solid ${T.border}` }}
        onWheel={onWheel} onMouseDown={onDown} onMouseMove={onMove}
        onMouseUp={stop} onMouseLeave={stop}>

        {/* viewBox é o que faz o desenho ESCALAR com o painel.
            Sem ele, as coordenadas são pixels absolutos: o conteúdo é
            desenhado para 1240px de largura e fica comprimido ou cortado em
            qualquer outro tamanho. `preserveAspectRatio` ancorado no topo
            evita o desenho flutuar no meio quando há poucos dispositivos. */}
        <svg
          width="100%" height="100%"
          viewBox={`0 0 ${WIDTH} ${Math.max(height, 420)}`}
          preserveAspectRatio="xMidYMin meet"
          style={{ cursor: drag.current ? "grabbing" : "grab", display: "block" }}>
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {/* Internet. Desenhada porque o gateway tem rota padrão; é a única
                ligação vertical que podemos afirmar. */}
            <g>
              <rect x={WIDTH / 2 - 78} y={TOP_INTERNET - 20} width="156" height="40" rx="20"
                fill={T.surface} stroke={T.border} strokeWidth="1" />
              <g transform={`translate(${WIDTH / 2 - 58}, ${TOP_INTERNET - 9})`} style={{ color: T.faint }}>
                <Globe size={18} />
              </g>
              <text x={WIDTH / 2 + 12} y={TOP_INTERNET + 5} textAnchor="middle"
                style={{ ...sans, fontSize: 12, fill: T.dim }}>Internet</text>
            </g>

            {!gateway && (
              /* Sem roteador identificado, não há como ligar a Internet ao
                 segmento. Dizer isso é mais honesto que desenhar uma linha
                 para o nada. */
              <text x={WIDTH / 2} y={TOP_GATEWAY + 6} textAnchor="middle"
                style={{ ...sans, fontSize: 12, fill: T.faint }}>
                Gateway não identificado nesta varredura
              </text>
            )}

            {gateway && (
              <>
                <line x1={WIDTH / 2} y1={TOP_INTERNET + 20} x2={WIDTH / 2} y2={TOP_GATEWAY - 24}
                  stroke={T.border} strokeWidth="1.5" />
                <Node
                  node={{ d: gateway, x: WIDTH / 2, y: TOP_GATEWAY, signals: gwSignals }}
                  size={25}
                  selected={selected?.id === gateway.id}
                  dimmed={!matches(gateway)}
                  onSelect={setSelected}
                />
                <line x1={WIDTH / 2} y1={TOP_GATEWAY + 44} x2={WIDTH / 2} y2={BUS_Y}
                  stroke={T.border} strokeWidth="1.5" />
              </>
            )}

            {/* Barramento do segmento.
                Esta é a única topologia que a varredura prova: todos estes
                dispositivos responderam ARP, logo estão no mesmo domínio de
                broadcast. Desenhar uma árvore com switches no meio seria
                inventar caminho que não foi medido — inaceitável em perícia. */}
            <line x1={40} y1={BUS_Y} x2={WIDTH - 40} y2={BUS_Y} stroke={T.accent} strokeWidth="2.5" opacity="0.55" />
            <line x1={40} y1={BUS_Y + 4} x2={WIDTH - 40} y2={BUS_Y + 4} stroke={T.accent} strokeWidth="1" opacity="0.2" />
            <rect x={40} y={BUS_Y - 13} width={296} height="26" rx="13" fill={T.bg} stroke={T.accent} strokeWidth="1" opacity="0.9" />
            <text x={54} y={BUS_Y + 5} style={{ ...mono, fontSize: 11, fill: T.accent }}>
              {cidr || "segmento local"}
            </text>
            <text x={54 + 108} y={BUS_Y + 5} style={{ ...sans, fontSize: 11, fill: T.dim }}>
              segmento L2 · {visible.length} dispositivos
            </text>

            {/* Faixas */}
            {bands.map((band) => (
              <g key={band.id}>
                <line x1={40} y1={band.y} x2={WIDTH - 40} y2={band.y} stroke={T.borderSubtle} strokeWidth="1" />
                {/* Rótulo e contagem na mesma linha, acima dos nós: em coluna
                    eles invadiam a primeira fileira de dispositivos. */}
                <text x={44} y={band.y + 20} style={{ ...sans, fontSize: 11, fill: T.faint }}>
                  {band.label}
                </text>
                <text x={44 + band.label.length * 6.5 + 12} y={band.y + 20}
                  style={{ ...mono, fontSize: 10, fill: T.faint, opacity: 0.65 }}>
                  {band.count}
                </text>
                {band.nodes.map((n) => (
                  <Node key={n.d.id} node={n}
                    selected={selected?.id === n.d.id}
                    dimmed={!matches(n.d)}
                    onSelect={setSelected} />
                ))}
              </g>
            ))}

            {visible.length === 0 && (
              <text x={WIDTH / 2} y={FIRST_BAND + 60} textAnchor="middle"
                style={{ ...sans, fontSize: 13, fill: T.faint }}>
                Nenhum dispositivo no filtro atual.
              </text>
            )}

            <rect x="0" y="0" width={WIDTH} height={height} fill="none" />
          </g>
        </svg>

      </div>

      {/* ---- legenda ----
          Fora da área de desenho, como rodapé. Antes era sobreposta ao SVG e
          colidia com os nós quando havia poucos dispositivos. */}
      <div className="flex items-center gap-4 flex-wrap shrink-0 px-1">
        <span className="text-xs" style={{ ...sans, color: T.faint }}>
          Anel: pior achado · Traço cortado: identidade fraca
        </span>
        <span className="flex items-center gap-3 flex-wrap">
          {[
            [T.accent2, "novo em 24h"],
            [SEVERITY.medium, "fora do expediente"],
            [SEVERITY.high, "MAC randomizado"],
            [SEVERITY.low, "trocou de IP"],
          ].map(([col, lbl]) => (
            <span key={lbl} className="flex items-center gap-1.5">
              <span className="rounded-full" style={{ width: 7, height: 7, background: col }} />
              <span className="text-xs" style={{ ...sans, color: T.faint }}>{lbl}</span>
            </span>
          ))}
        </span>
      </div>

      {/* ---- painel de evidência ---- */}
      {selected && (
        <EvidencePanel d={selected} now={now} onOpen={onOpen} onClose={() => setSelected(null)} />
      )}

      {!selected && (
        <p className="text-xs shrink-0" style={{ ...sans, color: T.faint }}>
          A linha horizontal representa o domínio de broadcast, a única topologia que a
          varredura comprova. A hierarquia física dos switches exige SNMP ou LLDP e não é
          desenhada por suposição.
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Evidência                                                          */
/* ------------------------------------------------------------------ */
function EvidencePanel({ d, now, onOpen, onClose }) {
  const Icon = ICON[d.kind] || CircleHelp;
  const signals = signalsOf(d, now);

  return (
    <div className="rounded-lg p-4 shrink-0"
      style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      <div className="flex items-start gap-3">
        <div className="rounded-md p-2 shrink-0" style={{ background: T.raised }}>
          <Icon size={18} style={{ color: T.accent }} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium" style={{ ...sans, color: T.text }}>
              {d.label || d.hostname || "Dispositivo sem nome"}
            </span>
            <span className="text-xs" style={{ ...sans, color: T.faint }}>
              {KIND_LABEL[d.kind] || d.kind}
            </span>
            {signals.map((s) => (
              <span key={s.id} className="rounded px-1.5 py-0.5 text-xs inline-flex items-center gap-1"
                style={{ ...sans, color: s.color, background: `${s.color}18`, border: `1px solid ${s.color}33` }}>
                {s.id === "mac" ? <Fingerprint size={10} /> : s.id === "fora" ? <AlertTriangle size={10} /> : null}
                {s.label}
              </span>
            ))}
          </div>

          {/* Dados de custódia: quem, quando, com que confiança. */}
          <div className="grid grid-cols-4 gap-x-6 gap-y-2 mt-3">
            <Ev label="Endereço IP" value={d.ip || "—"} m />
            <Ev label="Endereço MAC" value={d.mac || "—"} m />
            <Ev label="Fabricante" value={d.vendor || "—"} />
            <Ev label="Sistema" value={d.osGuess || "—"} />
            <Ev label="Primeira observação" value={fmt(d.firstSeen)} />
            <Ev label="Última observação" value={fmt(d.lastSeen)} />
            <Ev label="Confiança da identidade"
              value={{ high: "Alta", medium: "Média", low: "Baixa" }[d.identityConfidence] || "—"} />
            <Ev label="Endereços já usados" value={String(d.ipHistoryCount ?? 1)} m />
          </div>
        </div>

        <div className="flex flex-col gap-2 shrink-0">
          <button onClick={() => onOpen(d)}
            className="rounded-md px-3 h-8 text-sm"
            style={{ ...sans, background: T.raised, color: T.text, border: `1px solid ${T.border}` }}>
            Abrir detalhe
          </button>
          <button onClick={onClose} className="text-xs" style={{ ...sans, color: T.faint }}>
            fechar
          </button>
        </div>
      </div>

      {d.findingCount > 0 && (
        <div className="flex items-center gap-2 mt-3 pt-3" style={{ borderTop: `1px solid ${T.borderSubtle}` }}>
          <ShieldAlert size={14} style={{ color: SEVERITY[SEVERITY_BY_RANK[d.worstSeverityRank ?? 4]] }} />
          <span className="text-sm" style={{ ...sans, color: T.dim }}>
            {d.findingCount} {d.findingCount === 1 ? "achado aberto" : "achados abertos"} neste dispositivo
          </span>
        </div>
      )}
    </div>
  );
}

function Ev({ label, value, m }) {
  return (
    <span className="min-w-0">
      <span className="text-xs block" style={{ ...sans, color: T.faint }}>{label}</span>
      <span className="block truncate" style={{ ...(m ? mono : sans), color: T.text, fontSize: 13 }}>
        {value}
      </span>
    </span>
  );
}