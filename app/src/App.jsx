import { useEffect, useState } from "react";
import {
  Radar, Server, Network, AlertTriangle, GitCompareArrows, Settings2,
  Search, Play, Square, ShieldAlert, ShieldCheck, Wifi, Router, Printer,
  Monitor, Camera, HardDrive, CircleHelp, ChevronRight, ChevronDown,
  Check, EyeOff, Clock, Lock, Unlock, Cable, Inbox,
} from "lucide-react";
import { useSentinel, PHASE_LABEL } from "./lib/useSentinel";

/* ------------------------------------------------------------------ */
/*  Tokens                                                             */
/*  Espelham o tailwind.config.js. Cor vai em style inline porque o    */
/*  protótipo nasceu assim; migrar para classes Tailwind é opcional.   */
/* ------------------------------------------------------------------ */
const C = {
  app: "#090C12", panel: "#0F141D", raised: "#161D29", hover: "#1B2432",
  line: "#222C3C", lineSoft: "#19212E",
  text: "#E8ECF4", dim: "#9AA5B8", faint: "#6B7688",
  cyan: "#00C2FF", purple: "#7C3AED", ok: "#35D07F",
};

const SEV = {
  critical: { label: "Crítica", color: "#FF4D6D", rank: 0 },
  high: { label: "Alta", color: "#FF8A3D", rank: 1 },
  medium: { label: "Média", color: "#FFC94D", rank: 2 },
  low: { label: "Baixa", color: "#4DA8FF", rank: 3 },
  info: { label: "Info", color: "#7D8899", rank: 4 },
};
/** O backend manda `worstSeverityRank` como número. Este é o caminho inverso. */
const BY_RANK = ["critical", "high", "medium", "low", "info"];

const mono = { fontFamily: "'JetBrains Mono','SFMono-Regular',Consolas,monospace" };
const sans = { fontFamily: "Inter,-apple-system,'Segoe UI',sans-serif" };

const KIND_ICON = {
  router: Router, switch: Cable, firewall: Cable, server: Server,
  workstation: Monitor, printer: Printer, camera: Camera, nas: HardDrive,
  ap: Wifi, phone: Monitor, iot: CircleHelp, unknown: CircleHelp,
};
const KIND_LABEL = {
  router: "Roteador", switch: "Switch", firewall: "Firewall", server: "Servidor",
  workstation: "Estação", printer: "Impressora", camera: "Câmera", nas: "Storage",
  ap: "Access point", phone: "Celular", iot: "IoT", unknown: "Desconhecido",
};
const CHANGE_LABEL = {
  device_new: "Dispositivo novo", device_gone: "Dispositivo ausente",
  device_returned: "Dispositivo voltou", port_opened: "Porta aberta",
  port_closed: "Porta fechada", ip_changed: "IP alterado",
  mac_changed: "MAC alterado", hostname_changed: "Nome alterado",
  vendor_conflict: "Fabricante divergente", os_changed: "Sistema alterado",
};

/** Epoch em segundos para algo legível. */
function ago(epoch) {
  if (!epoch) return "—";
  const s = Math.floor(Date.now() / 1000) - epoch;
  if (s < 90) return "agora";
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h`;
  return `${Math.floor(s / 86400)} d`;
}
function dateOf(epoch) {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleString("pt-BR", {
    day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

/* ------------------------------------------------------------------ */
/*  Primitivos                                                         */
/* ------------------------------------------------------------------ */
function Panel({ title, action, children, pad = true }) {
  return (
    <section className="rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
      {title && (
        <header className="flex items-center justify-between px-4 h-11" style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
          <h2 className="text-sm font-medium" style={{ ...sans, color: C.text }}>{title}</h2>
          {action}
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

function SevDot({ sev, size = 8 }) {
  const s = SEV[sev] || SEV.info;
  return <span className="inline-block rounded-full shrink-0" style={{ width: size, height: size, background: s.color }} />;
}

function SevTag({ sev }) {
  const s = SEV[sev] || SEV.info;
  return (
    <span className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs"
      style={{ ...sans, color: s.color, background: `${s.color}18`, border: `1px solid ${s.color}33` }}>
      <SevDot sev={sev} size={6} />{s.label}
    </span>
  );
}

function ConfTag({ conf }) {
  const map = {
    confirmed: ["Confirmado", C.ok, Lock], likely: ["Provável", C.dim, Unlock],
    possible: ["Possível", C.faint, Unlock], high: ["Alta", C.ok, Lock],
    medium: ["Média", C.dim, Unlock], low: ["Baixa", C.faint, Unlock],
  };
  const [t, col, Icon] = map[conf] || map.possible;
  return <span className="inline-flex items-center gap-1 text-xs" style={{ ...sans, color: col }}><Icon size={11} />{t}</span>;
}

function Mono({ children, dim }) {
  return <span style={{ ...mono, color: dim ? C.dim : C.text, fontSize: 13 }}>{children}</span>;
}

/** Estado vazio. Aparece antes da primeira varredura, e é a primeira coisa
 *  que o usuário vê ao abrir o aplicativo: precisa dizer o que fazer. */
function Empty({ icon: Icon = Inbox, title, hint, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16">
      <Icon size={28} style={{ color: C.faint }} />
      <p className="text-sm" style={{ ...sans, color: C.dim }}>{title}</p>
      {hint && <p className="text-xs text-center" style={{ ...sans, color: C.faint, maxWidth: 380 }}>{hint}</p>}
      {action}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Visão geral                                                        */
/* ------------------------------------------------------------------ */
function Overview({ devices, changes, findings, go, onScan }) {
  if (devices.length === 0) {
    return (
      <Panel>
        <Empty
          icon={Radar}
          title="Nenhuma varredura ainda"
          hint="Clique em Escanear rede para descobrir o que está conectado. A primeira varredura leva de 30 a 60 segundos."
          action={
            <button onClick={() => onScan()} className="rounded-md px-3.5 h-9 text-sm font-medium mt-1"
              style={{ ...sans, background: C.cyan, color: "#06090F" }}>
              Escanear rede
            </button>
          }
        />
      </Panel>
    );
  }

  const online = devices.filter((d) => d.missCount === 0).length;
  const crit = findings.filter((f) => f.severity === "critical");
  const unseen = changes.filter((c) => !c.acknowledged);
  const counts = Object.keys(SEV).map((k) => ({ k, n: findings.filter((f) => f.severity === k).length }));
  const max = Math.max(...counts.map((c) => c.n), 1);

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-4 gap-4">
        <Metric label="Dispositivos ativos" value={online} sub={`${devices.length - online} ausente(s)`} accent={C.cyan} />
        <Metric label="Achados críticos" value={crit.length} sub="exigem ação hoje" accent={SEV.critical.color} />
        <Metric label="Achados abertos" value={findings.length} sub="total em toda a rede" accent={C.purple} />
        <Metric label="Mudanças não vistas" value={unseen.length} sub="desde a última visita" accent={C.ok} />
      </div>

      {crit.length > 0 && (
        <div className="rounded-lg p-4 flex items-start gap-3"
          style={{ background: "#FF4D6D12", border: `1px solid ${SEV.critical.color}44` }}>
          <ShieldAlert size={18} style={{ color: SEV.critical.color }} className="mt-0.5 shrink-0" />
          <div className="min-w-0">
            <p className="text-sm font-medium" style={{ ...sans, color: C.text }}>
              {crit.length} {crit.length === 1 ? "problema crítico" : "problemas críticos"} nesta rede
            </p>
            <button onClick={() => go("findings")} className="mt-2 inline-flex items-center gap-1 text-sm"
              style={{ ...sans, color: SEV.critical.color }}>
              Ver os achados <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2">
          <Panel title="Mudanças recentes"
            action={<button onClick={() => go("changes")} className="text-xs" style={{ ...sans, color: C.cyan }}>Ver tudo</button>}
            pad={false}>
            {unseen.length === 0 && (
              <div className="px-4 py-8 text-center">
                <p className="text-sm" style={{ ...sans, color: C.faint }}>Nada mudou desde a última varredura.</p>
              </div>
            )}
            {unseen.slice(0, 6).map((c) => (
              <button key={c.id} onClick={() => go("changes")}
                className="w-full flex items-center gap-3 px-4 h-14 text-left"
                style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
                <SevDot sev={c.severity} />
                <div className="flex-1 min-w-0">
                  <span className="text-sm" style={{ ...sans, color: C.text }}>{CHANGE_LABEL[c.changeType] || c.changeType}</span>
                  <span className="text-sm ml-2" style={{ ...mono, color: C.dim }}>{c.deviceIp || c.deviceLabel || ""}</span>
                  <p className="text-xs truncate" style={{ ...sans, color: C.faint }}>{c.after || ""}</p>
                </div>
                <span className="text-xs shrink-0" style={{ ...sans, color: C.faint }}>{ago(c.detectedAt)}</span>
              </button>
            ))}
          </Panel>
        </div>

        <Panel title="Achados por severidade">
          <div className="flex flex-col gap-3">
            {counts.map(({ k, n }) => (
              <div key={k} className="flex items-center gap-3">
                <span className="text-xs w-14 shrink-0" style={{ ...sans, color: C.dim }}>{SEV[k].label}</span>
                <div className="flex-1 h-1.5 rounded-full" style={{ background: C.raised }}>
                  <div className="h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: SEV[k].color }} />
                </div>
                <span className="text-sm w-5 text-right" style={{ ...mono, color: C.text }}>{n}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

function Metric({ label, value, sub, accent }) {
  return (
    <div className="rounded-lg p-4" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
      <p className="text-xs" style={{ ...sans, color: C.faint }}>{label}</p>
      <p className="mt-2" style={{ ...mono, color: accent, fontSize: 30, lineHeight: 1, fontWeight: 500 }}>{value}</p>
      <p className="text-xs mt-2" style={{ ...sans, color: C.faint }}>{sub}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Dispositivos                                                       */
/* ------------------------------------------------------------------ */
function Devices({ devices, onOpen, scanning, onScan }) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("all");

  if (devices.length === 0 && !scanning) {
    return (
      <Panel>
        <Empty icon={Server} title="Nenhum dispositivo no inventário"
          hint="Rode a primeira varredura para preencher o inventário."
          action={
            <button onClick={() => onScan()} className="rounded-md px-3.5 h-9 text-sm font-medium mt-1"
              style={{ ...sans, background: C.cyan, color: "#06090F" }}>Escanear rede</button>
          } />
      </Panel>
    );
  }

  const kinds = ["all", ...new Set(devices.map((d) => d.kind))];
  const rows = devices.filter((d) => {
    if (kind !== "all" && d.kind !== kind) return false;
    const hay = `${d.label || ""} ${d.ip || ""} ${d.mac || ""} ${d.vendor || ""}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  });
  const cols = "1.6fr 1fr 1.3fr 1fr .7fr .9fr .8fr";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 rounded-md px-3 h-9 flex-1"
          style={{ background: C.panel, border: `1px solid ${C.line}` }}>
          <Search size={14} style={{ color: C.faint }} />
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="Filtrar por nome, IP, MAC ou fabricante"
            className="bg-transparent outline-none flex-1 text-sm" style={{ ...sans, color: C.text }} />
        </div>
        <div className="flex gap-1 rounded-md p-1" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
          {kinds.map((k) => (
            <button key={k} onClick={() => setKind(k)} className="px-2.5 h-7 rounded text-xs"
              style={{ ...sans, background: kind === k ? C.raised : "transparent", color: kind === k ? C.text : C.faint }}>
              {k === "all" ? "Todos" : KIND_LABEL[k] || k}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
        <div className="grid px-4 h-9 items-center text-xs"
          style={{ ...sans, color: C.faint, borderBottom: `1px solid ${C.lineSoft}`, gridTemplateColumns: cols }}>
          <span>Dispositivo</span><span>Endereço</span><span>MAC</span>
          <span>Sistema</span><span>Portas</span><span>Achados</span><span>Visto</span>
        </div>

        {rows.map((d) => {
          const Icon = KIND_ICON[d.kind] || CircleHelp;
          const sev = d.worstSeverityRank !== null ? BY_RANK[d.worstSeverityRank] : null;
          const offline = d.missCount > 0;
          return (
            <button key={d.id} onClick={() => onOpen(d)}
              className="w-full grid px-4 h-14 items-center text-left relative"
              style={{ borderBottom: `1px solid ${C.lineSoft}`, gridTemplateColumns: cols }}>
              <span className="absolute left-0 top-0 bottom-0" style={{ width: 3, background: sev ? SEV[sev].color : "transparent" }} />
              <span className="flex items-center gap-2.5 min-w-0">
                <Icon size={15} style={{ color: offline ? C.faint : C.dim }} className="shrink-0" />
                <span className="min-w-0">
                  <span className="text-sm block truncate"
                    style={{ ...sans, color: d.label ? C.text : C.faint, fontStyle: d.label ? "normal" : "italic" }}>
                    {d.label || "sem nome"}
                  </span>
                  <span className="text-xs" style={{ ...sans, color: C.faint }}>{KIND_LABEL[d.kind] || d.kind}</span>
                </span>
              </span>
              <Mono>{d.ip || "—"}</Mono>
              <span className="min-w-0">
                <Mono dim>{d.mac || "—"}</Mono>
                <span className="text-xs block truncate" style={{ ...sans, color: C.faint }}>{d.vendor || ""}</span>
              </span>
              <span className="text-sm truncate" style={{ ...sans, color: C.dim }}>{d.osGuess || "—"}</span>
              <Mono dim>{d.openPorts}</Mono>
              <span>{sev ? <SevTag sev={sev} /> : <span className="text-xs" style={{ ...sans, color: C.faint }}>—</span>}</span>
              <span className="flex items-center gap-1.5">
                <span className="rounded-full" style={{ width: 6, height: 6, background: offline ? C.faint : C.ok }} />
                <span className="text-xs" style={{ ...sans, color: offline ? C.faint : C.dim }}>{ago(d.lastSeen)}</span>
              </span>
            </button>
          );
        })}

        {scanning && (
          <div className="flex items-center gap-2.5 px-4 h-14" style={{ color: C.cyan }}>
            <Radar size={15} className="animate-spin" style={{ animationDuration: "2.5s" }} />
            <span className="text-sm" style={{ ...sans }}>Procurando mais dispositivos…</span>
          </div>
        )}
        {!scanning && rows.length === 0 && (
          <div className="px-4 py-12 text-center">
            <p className="text-sm" style={{ ...sans, color: C.dim }}>Nenhum dispositivo corresponde ao filtro.</p>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Detalhe                                                            */
/* ------------------------------------------------------------------ */
function DeviceDetail({ device, rules, loadDetail, onBack, onRename, onAccept }) {
  const [tab, setTab] = useState("portas");
  const [detail, setDetail] = useState(null);
  const [err, setErr] = useState(null);

  // Carregado sob demanda: a lista não pode trazer portas e achados de todos
  // os dispositivos, seriam três consultas por linha.
  useEffect(() => {
    let alive = true;
    setDetail(null);
    setErr(null);
    loadDetail(device.id)
      .then((d) => alive && setDetail(d))
      .catch((e) => alive && setErr(String(e)));
    return () => { alive = false; };
  }, [device.id, loadDetail]);

  const Icon = KIND_ICON[device.kind] || CircleHelp;

  return (
    <div className="flex flex-col gap-4">
      <button onClick={onBack} className="flex items-center gap-1 text-sm self-start" style={{ ...sans, color: C.cyan }}>
        <ChevronRight size={14} className="rotate-180" /> Dispositivos
      </button>

      <div className="rounded-lg p-5" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
        <div className="flex items-start gap-4">
          <div className="rounded-md p-2.5" style={{ background: C.raised }}>
            <Icon size={22} style={{ color: C.cyan }} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3">
              <h1 style={{ ...sans, color: device.label ? C.text : C.faint, fontSize: 20, fontWeight: 600,
                fontStyle: device.label ? "normal" : "italic" }}>
                {device.label || "Dispositivo sem nome"}
              </h1>
              <ConfTag conf={device.identityConfidence} />
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-1 mt-3">
              <Field label="IP" value={device.ip || "—"} />
              <Field label="MAC" value={device.mac || "—"} />
              <Field label="Fabricante" value={device.vendor || "—"} sans />
              <Field label="Sistema" value={device.osGuess || "—"} sans />
              <Field label="Tipo" value={KIND_LABEL[device.kind] || device.kind} sans />
            </div>
          </div>
          <button onClick={() => {
            const nome = window.prompt("Nome do dispositivo", device.label || "");
            if (nome) onRename(device.id, nome);
          }} className="rounded-md px-3 h-8 text-sm shrink-0"
            style={{ ...sans, color: C.text, background: C.raised, border: `1px solid ${C.line}` }}>
            Renomear
          </button>
        </div>
      </div>

      <div className="flex gap-1">
        {["portas", "achados", "endereços"].map((t) => (
          <button key={t} onClick={() => setTab(t)} className="px-3 h-8 rounded-md text-sm"
            style={{ ...sans, background: tab === t ? C.panel : "transparent", color: tab === t ? C.text : C.faint,
              border: `1px solid ${tab === t ? C.line : "transparent"}` }}>
            {t[0].toUpperCase() + t.slice(1)}
            {t === "achados" && detail?.findings.length > 0 && (
              <span className="ml-1.5" style={{ ...mono, color: SEV.high.color }}>{detail.findings.length}</span>
            )}
          </button>
        ))}
      </div>

      {err && <Panel><p className="text-sm" style={{ ...sans, color: SEV.high.color }}>{err}</p></Panel>}
      {!detail && !err && <Panel><p className="text-sm" style={{ ...sans, color: C.faint }}>Carregando…</p></Panel>}

      {detail && tab === "portas" && (
        <Panel pad={false}>
          {detail.services.length === 0 ? (
            <Empty title="Nenhuma porta aberta encontrada"
              hint="Ou o dispositivo não expõe serviço, ou a varredura rodou em perfil de presença." />
          ) : (
            <>
              <div className="grid px-4 h-9 items-center text-xs"
                style={{ ...sans, color: C.faint, borderBottom: `1px solid ${C.lineSoft}`, gridTemplateColumns: ".4fr .6fr 2fr" }}>
                <span>Porta</span><span>Serviço</span><span>Banner</span>
              </div>
              {detail.services.map((p) => (
                <div key={`${p.protocol}/${p.port}`} className="grid px-4 h-11 items-center"
                  style={{ borderBottom: `1px solid ${C.lineSoft}`, gridTemplateColumns: ".4fr .6fr 2fr" }}>
                  <Mono>{p.port}</Mono>
                  <span className="text-sm" style={{ ...sans, color: C.dim }}>{p.serviceName || p.protocol}</span>
                  <Mono dim>{(p.banner || "—").split("\n")[0]}</Mono>
                </div>
              ))}
            </>
          )}
        </Panel>
      )}

      {detail && tab === "achados" && (
        <div className="flex flex-col gap-3">
          {detail.findings.length === 0 ? (
            <Panel>
              <div className="flex items-center gap-2.5 py-6 justify-center">
                <ShieldCheck size={18} style={{ color: C.ok }} />
                <span className="text-sm" style={{ ...sans, color: C.dim }}>Nenhum problema encontrado neste dispositivo.</span>
              </div>
            </Panel>
          ) : (
            detail.findings.map((f) => (
              <FindingCard key={f.id} finding={f} rule={rules[f.ruleId]} onAccept={onAccept} />
            ))
          )}
        </div>
      )}

      {detail && tab === "endereços" && (
        <Panel pad={false}>
          <div className="grid px-4 h-9 items-center text-xs"
            style={{ ...sans, color: C.faint, borderBottom: `1px solid ${C.lineSoft}`, gridTemplateColumns: ".4fr 1fr .6fr" }}>
            <span>Tipo</span><span>Valor</span><span>Situação</span>
          </div>
          {detail.addresses.map((a, i) => (
            <div key={i} className="grid px-4 h-11 items-center"
              style={{ borderBottom: `1px solid ${C.lineSoft}`, gridTemplateColumns: ".4fr 1fr .6fr" }}>
              <span className="text-sm" style={{ ...sans, color: C.dim }}>{a.kind.toUpperCase()}</span>
              <Mono>{a.value}</Mono>
              <span className="text-xs" style={{ ...sans, color: a.isCurrent ? C.ok : C.faint }}>
                {a.isCurrent ? "atual" : "histórico"}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-3 px-4 h-14">
            <Clock size={13} style={{ color: C.faint }} />
            <span className="text-sm" style={{ ...sans, color: C.faint }}>
              Visto pela primeira vez em {dateOf(detail.firstSeen)}
            </span>
          </div>
        </Panel>
      )}
    </div>
  );
}

function Field({ label, value, sans: isSans }) {
  return (
    <span>
      <span className="text-xs block" style={{ ...sans, color: C.faint }}>{label}</span>
      <span style={{ ...(isSans ? sans : mono), color: C.text, fontSize: 13 }}>{value}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Achados                                                            */
/* ------------------------------------------------------------------ */
function FindingCard({ finding, rule, affected, onAccept }) {
  const [open, setOpen] = useState(false);
  // Regra ausente do catálogo indica versão de banco mais nova que o binário.
  // Degrada mostrando o id em vez de quebrar a tela.
  const r = rule || { title: finding?.ruleId || "Regra desconhecida", why: "", fix: "" };
  const sev = finding?.severity || r.severity || "info";

  return (
    <div className="rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
      <div className="flex">
        <span style={{ width: 3, background: SEV[sev].color }} />
        <button onClick={() => setOpen(!open)} className="flex-1 flex items-center gap-3 px-4 py-3 text-left">
          {open ? <ChevronDown size={14} style={{ color: C.faint }} /> : <ChevronRight size={14} style={{ color: C.faint }} />}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5">
              <span className="text-sm font-medium" style={{ ...sans, color: C.text }}>{r.title}</span>
              <Mono dim>{finding?.ruleId}</Mono>
            </div>
            {affected && (
              <p className="text-xs mt-1" style={{ ...sans, color: C.faint }}>
                {affected.length} dispositivo{affected.length > 1 ? "s" : ""} afetado{affected.length > 1 ? "s" : ""}
              </p>
            )}
            {!affected && finding?.evidence && (
              <p className="text-xs mt-1 truncate" style={{ ...mono, color: C.faint }}>{finding.evidence}</p>
            )}
          </div>
          <ConfTag conf={finding?.confidence || r.confidence} />
          <SevTag sev={sev} />
        </button>
      </div>

      {open && (
        <div className="px-4 pb-4 pt-1 flex flex-col gap-4" style={{ paddingLeft: 37 }}>
          {r.why && (
            <div>
              <p className="text-xs mb-1.5" style={{ ...sans, color: C.faint }}>Por que isso importa</p>
              <p className="text-sm leading-relaxed" style={{ ...sans, color: C.dim, maxWidth: "72ch" }}>{r.why}</p>
            </div>
          )}
          {r.fix && (
            <div>
              <p className="text-xs mb-1.5" style={{ ...sans, color: C.faint }}>Como corrigir</p>
              <p className="text-sm leading-relaxed" style={{ ...sans, color: C.dim, maxWidth: "72ch" }}>{r.fix}</p>
            </div>
          )}
          {affected && (
            <div>
              <p className="text-xs mb-1.5" style={{ ...sans, color: C.faint }}>Afetados</p>
              <div className="flex flex-wrap gap-2">
                {affected.map((f) => (
                  <span key={f.id} className="rounded px-2 py-1 text-xs"
                    style={{ ...mono, background: C.raised, color: C.dim, border: `1px solid ${C.line}` }}>
                    {f.deviceIp || f.deviceId.slice(0, 8)}{f.scope ? ` · ${f.scope}` : ""}
                  </span>
                ))}
              </div>
            </div>
          )}
          {onAccept && finding && (
            <div className="flex gap-2">
              <button onClick={() => {
                const motivo = window.prompt("Por que aceitar este risco?");
                if (motivo) onAccept(finding.id, motivo);
              }} className="inline-flex items-center gap-1.5 rounded-md px-2.5 h-8 text-sm"
                style={{ ...sans, background: C.raised, color: C.dim, border: `1px solid ${C.line}` }}>
                <EyeOff size={13} /> Aceitar risco
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Findings({ findings, rules, onAccept }) {
  if (findings.length === 0) {
    return (
      <Panel>
        <Empty icon={ShieldCheck} title="Nenhum achado aberto"
          hint="Ou a rede está limpa, ou ainda não houve varredura com verificação de portas." />
      </Panel>
    );
  }

  // Agrupado por regra: quarenta dispositivos com SNMP público são um achado
  // com quarenta afetados, não quarenta linhas repetidas.
  const byRule = {};
  findings.forEach((f) => { (byRule[f.ruleId] ||= []).push(f); });
  const ids = Object.keys(byRule).sort(
    (a, b) => SEV[byRule[a][0].severity].rank - SEV[byRule[b][0].severity].rank,
  );

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm" style={{ ...sans, color: C.dim }}>
        {ids.length} {ids.length === 1 ? "regra disparou" : "regras dispararam"} em{" "}
        {new Set(findings.map((f) => f.deviceId)).size} dispositivos.
      </p>
      {ids.map((id) => (
        <FindingCard key={id} finding={byRule[id][0]} rule={rules[id]}
          affected={byRule[id]} onAccept={onAccept} />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Mudanças                                                           */
/* ------------------------------------------------------------------ */
function Changes({ changes, onAck }) {
  const [showAck, setShowAck] = useState(false);
  const rows = changes.filter((c) => showAck || !c.acknowledged);

  if (changes.length === 0) {
    return (
      <Panel>
        <Empty icon={GitCompareArrows} title="Nenhuma mudança registrada"
          hint="Mudanças aparecem a partir da segunda varredura, comparando com o estado anterior." />
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm" style={{ ...sans, color: C.dim }}>
          Comparação com o estado da varredura anterior.
        </p>
        <button onClick={() => setShowAck(!showAck)} className="text-sm" style={{ ...sans, color: C.cyan }}>
          {showAck ? "Ocultar já vistas" : "Mostrar já vistas"}
        </button>
      </div>
      <Panel pad={false}>
        {rows.map((c) => (
          <div key={c.id} className="flex items-center gap-3 px-4 h-16 relative"
            style={{ borderBottom: `1px solid ${C.lineSoft}`, opacity: c.acknowledged ? 0.5 : 1 }}>
            <span className="absolute left-0 top-0 bottom-0"
              style={{ width: 3, background: c.acknowledged ? "transparent" : SEV[c.severity].color }} />
            <SevDot sev={c.severity} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm" style={{ ...sans, color: C.text }}>{CHANGE_LABEL[c.changeType] || c.changeType}</span>
                <Mono dim>{c.deviceIp || c.deviceLabel || ""}</Mono>
              </div>
              <p className="text-xs mt-0.5 truncate" style={{ ...mono, color: C.faint }}>
                {c.before ? `${c.before} → ${c.after || "—"}` : c.after || ""}
              </p>
            </div>
            <span className="text-xs shrink-0" style={{ ...sans, color: C.faint }}>{ago(c.detectedAt)}</span>
            {!c.acknowledged && (
              <button onClick={() => onAck(c.id)} className="rounded-md px-2.5 h-7 text-xs shrink-0"
                style={{ ...sans, background: C.raised, color: C.dim, border: `1px solid ${C.line}` }}>
                Marcar como vista
              </button>
            )}
          </div>
        ))}
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Mapa                                                               */
/* ------------------------------------------------------------------ */
function MapView({ devices, onOpen }) {
  if (devices.length === 0) {
    return <Panel><Empty icon={Network} title="Sem dados para desenhar o mapa" /></Panel>;
  }

  const gw = devices.find((d) => d.kind === "router") || devices[0];
  const sw = devices.find((d) => d.kind === "switch");
  const leaves = devices.filter((d) => d !== gw && d !== sw);

  const W = 980, cols = 7, cw = W / cols;
  const swY = 150, leafY = 290;
  const rows = Math.ceil(leaves.length / cols);
  const H = leafY + rows * 110 + 20;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm" style={{ ...sans, color: C.dim }}>
        Hierarquia da sub-rede. A borda colorida indica o achado mais grave de cada dispositivo.
      </p>
      <div className="rounded-lg p-4 overflow-x-auto" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", minWidth: 900 }}>
          {sw && <line x1={W / 2} y1={62} x2={W / 2} y2={swY - 22} stroke={C.line} strokeWidth="1.5" />}
          {leaves.map((_, i) => {
            const x = cw * (i % cols) + cw / 2;
            const y = leafY + Math.floor(i / cols) * 110;
            const from = sw ? swY + 22 : 62;
            return <path key={i} d={`M${W / 2},${from} L${W / 2},${y - 55} L${x},${y - 55} L${x},${y - 26}`}
              fill="none" stroke={C.line} strokeWidth="1.5" />;
          })}
          <MapNode x={W / 2} y={40} d={gw} onOpen={onOpen} root />
          {sw && <MapNode x={W / 2} y={swY} d={sw} onOpen={onOpen} />}
          {leaves.map((d, i) => (
            <MapNode key={d.id} d={d} onOpen={onOpen}
              x={cw * (i % cols) + cw / 2} y={leafY + Math.floor(i / cols) * 110} />
          ))}
        </svg>
      </div>
    </div>
  );
}

function MapNode({ x, y, d, onOpen, root }) {
  const r = root ? 22 : 18;
  const sev = d.worstSeverityRank !== null ? BY_RANK[d.worstSeverityRank] : null;
  const color = sev ? SEV[sev].color : d.missCount === 0 ? C.line : C.faint;
  const short = (d.ip || "").split(".").slice(2).join(".") || "?";
  return (
    <g onClick={() => onOpen(d)} style={{ cursor: "pointer" }}>
      <circle cx={x} cy={y} r={r} fill={C.raised} stroke={color} strokeWidth={sev ? 2 : 1.5} />
      <text x={x} y={y + 4} textAnchor="middle" style={{ ...sans, fontSize: 11, fill: C.dim }}>
        {(KIND_LABEL[d.kind] || "?").slice(0, 3)}
      </text>
      <text x={x} y={y + r + 15} textAnchor="middle" style={{ ...mono, fontSize: 10, fill: C.text }}>{short}</text>
      <text x={x} y={y + r + 28} textAnchor="middle" style={{ ...sans, fontSize: 10, fill: C.faint }}>
        {(d.label || "sem nome").slice(0, 15)}
      </text>
    </g>
  );
}

/* ------------------------------------------------------------------ */
/*  Configurações                                                      */
/* ------------------------------------------------------------------ */
function SettingsView({ caps, iface, cidr, rules }) {
  const total = Object.keys(rules).length;
  const off = Object.values(rules).filter((r) => !r.enabled).length;

  return (
    <div className="flex flex-col gap-4" style={{ maxWidth: 760 }}>
      <Panel title="Interface de rede">
        <div className="flex flex-col gap-3">
          <Row label="Interface" value={iface || "—"} />
          <Row label="Faixa detectada" value={cidr || "—"} />
          <p className="text-sm leading-relaxed pt-1" style={{ ...sans, color: C.faint, maxWidth: "70ch" }}>
            O sensor enxerga apenas a VLAN onde está conectado. Outras VLANs precisam de uma
            instância própria ou de leitura via SNMP no roteador.
          </p>
        </div>
      </Panel>

      <Panel title="Permissões do sistema">
        <div className="flex flex-col gap-3">
          <Capability on name="Varredura de portas TCP" note="Não exige privilégio" />
          <Capability on={caps?.arpActive} name="Varredura ARP ativa" note="Exige CAP_NET_RAW no binário" />
          <Capability on={caps?.passiveListen} name="Escuta passiva de broadcast" note="Exige CAP_NET_RAW no binário" />
          {caps?.reason && (
            <div className="rounded-md p-3 flex gap-2.5 mt-1"
              style={{ background: `${SEV.medium.color}12`, border: `1px solid ${SEV.medium.color}33` }}>
              <AlertTriangle size={15} style={{ color: SEV.medium.color }} className="mt-0.5 shrink-0" />
              <p className="text-sm leading-relaxed" style={{ ...sans, color: C.dim, maxWidth: "68ch" }}>{caps.reason}</p>
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Catálogo de regras">
        <div className="flex flex-col gap-3">
          <Row label="Regras carregadas" value={String(total)} />
          <Row label="Desligadas por padrão" value={String(off)} />
          <p className="text-sm leading-relaxed pt-1" style={{ ...sans, color: C.faint, maxWidth: "70ch" }}>
            As regras desligadas testam credencial padrão. Elas tentam autenticar, o que pode
            bloquear conta em sistema com política de lockout, e por isso exigem consentimento
            explícito por dispositivo.
          </p>
        </div>
      </Panel>

      <Panel title="Segurança da varredura">
        <div className="rounded-md p-3 flex gap-2.5"
          style={{ background: `${SEV.medium.color}12`, border: `1px solid ${SEV.medium.color}33` }}>
          <AlertTriangle size={15} style={{ color: SEV.medium.color }} className="mt-0.5 shrink-0" />
          <p className="text-sm leading-relaxed" style={{ ...sans, color: C.dim, maxWidth: "68ch" }}>
            Impressoras e equipamento industrial antigo podem travar durante varredura ativa.
            Adicione esses endereços às faixas excluídas antes da primeira execução.
          </p>
        </div>
      </Panel>
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between h-8">
      <span className="text-sm" style={{ ...sans, color: C.dim }}>{label}</span>
      <Mono>{value}</Mono>
    </div>
  );
}

function Capability({ on, name, note }) {
  return (
    <div className="flex items-center gap-2.5 h-8">
      <span className="rounded-full shrink-0" style={{ width: 7, height: 7, background: on ? C.ok : C.faint }} />
      <span className="text-sm" style={{ ...sans, color: on ? C.text : C.faint }}>{name}</span>
      <span className="text-xs" style={{ ...sans, color: C.faint }}>· {note}</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Shell                                                              */
/* ------------------------------------------------------------------ */
const NAV = [
  { id: "overview", label: "Visão geral", icon: Radar },
  { id: "devices", label: "Dispositivos", icon: Server },
  { id: "findings", label: "Achados", icon: AlertTriangle },
  { id: "changes", label: "Mudanças", icon: GitCompareArrows },
  { id: "map", label: "Mapa", icon: Network },
  { id: "settings", label: "Configurações", icon: Settings2 },
];

export default function App() {
  const {
    iface, cidr, caps, devices, changes, findings, rules, loading, scan,
    startScan, cancelScan, ackChange, renameDevice, loadDetail, acceptFinding,
    unseenChanges,
  } = useSentinel();

  const [view, setView] = useState("overview");
  const [selected, setSelected] = useState(null);

  const open = (d) => { setSelected(d); setView("device"); };

  return (
    <div className="flex" style={{ background: C.app, color: C.text, minHeight: "100vh", ...sans }}>
      <nav className="w-52 shrink-0 flex flex-col" style={{ background: C.panel, borderRight: `1px solid ${C.line}` }}>
        <div className="h-14 flex items-center gap-2.5 px-4" style={{ borderBottom: `1px solid ${C.line}` }}>
          <span className="rounded flex items-center justify-center"
            style={{ width: 24, height: 24, background: `linear-gradient(135deg, ${C.cyan}, ${C.purple})` }}>
            <Radar size={14} color="#06090F" />
          </span>
          <span style={{ fontSize: 14, fontWeight: 600, letterSpacing: "-0.01em" }}>SentinelStack</span>
        </div>

        <div className="flex flex-col gap-0.5 p-2">
          {NAV.map((n) => {
            const active = view === n.id || (view === "device" && n.id === "devices");
            return (
              <button key={n.id} onClick={() => { setView(n.id); setSelected(null); }}
                className="flex items-center gap-2.5 h-9 px-2.5 rounded-md text-sm relative"
                style={{ background: active ? C.raised : "transparent", color: active ? C.text : C.dim }}>
                {active && <span className="absolute left-0 rounded-r" style={{ width: 2, height: 16, background: C.cyan }} />}
                <n.icon size={15} style={{ color: active ? C.cyan : C.faint }} />
                {n.label}
                {n.id === "changes" && unseenChanges > 0 && (
                  <span className="ml-auto rounded px-1.5 text-xs"
                    style={{ ...mono, background: `${C.purple}2A`, color: C.purple }}>{unseenChanges}</span>
                )}
                {n.id === "findings" && findings.length > 0 && (
                  <span className="ml-auto rounded px-1.5 text-xs"
                    style={{ ...mono, background: `${SEV.high.color}2A`, color: SEV.high.color }}>{findings.length}</span>
                )}
              </button>
            );
          })}
        </div>

        <div className="mt-auto p-3">
          <div className="rounded-md p-2.5" style={{ background: C.raised, border: `1px solid ${C.line}` }}>
            <div className="flex items-center gap-1.5">
              {caps?.arpActive ? <Lock size={11} style={{ color: C.ok }} />
                : <Unlock size={11} style={{ color: SEV.medium.color }} />}
              <span className="text-xs" style={{ color: caps?.arpActive ? C.ok : SEV.medium.color }}>
                {caps?.arpActive ? "Modo completo" : "Modo limitado"}
              </span>
            </div>
            <p className="text-xs mt-1 leading-snug" style={{ color: C.faint }}>
              {caps?.arpActive ? "ARP e escuta passiva disponíveis." : "Apenas varredura TCP."}
            </p>
          </div>
        </div>
      </nav>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 shrink-0 flex items-center gap-4 px-6"
          style={{ borderBottom: `1px solid ${C.line}`, background: C.panel }}>
          <div className="flex items-center gap-2">
            <Mono dim>{iface || "—"}</Mono>
            <span style={{ color: C.faint }}>·</span>
            <Mono>{cidr || "—"}</Mono>
          </div>
          <span className="text-xs" style={{ color: C.faint }}>
            {scan.running
              ? `${PHASE_LABEL[scan.phase] || "Varrendo"}… ${scan.percent}%`
              : scan.lastResult
                ? `${scan.lastResult.found} dispositivos · ${scan.lastResult.new} novos`
                : "Nenhuma varredura nesta sessão"}
          </span>
          {scan.error && <span className="text-xs" style={{ color: SEV.critical.color }}>{scan.error}</span>}
          <button onClick={scan.running ? cancelScan : () => startScan()}
            disabled={!iface || !cidr}
            className="ml-auto inline-flex items-center gap-2 rounded-md px-3.5 h-9 text-sm font-medium"
            style={{
              background: scan.running ? C.raised : C.cyan,
              color: scan.running ? C.text : "#06090F",
              border: `1px solid ${scan.running ? C.line : C.cyan}`,
              opacity: !iface || !cidr ? 0.5 : 1,
            }}>
            {scan.running ? <><Square size={13} /> Parar</> : <><Play size={13} /> Escanear rede</>}
          </button>
        </header>

        {scan.running && (
          <div style={{ height: 2, background: C.raised }}>
            <div style={{ height: "100%", width: `${scan.percent}%`, background: C.cyan, transition: "width .35s linear" }} />
          </div>
        )}

        <main className="flex-1 p-6 overflow-auto">
          {loading ? (
            <Panel><p className="text-sm" style={{ ...sans, color: C.faint }}>Abrindo o banco…</p></Panel>
          ) : (
            <>
              {view === "overview" && (
                <Overview devices={devices} changes={changes} findings={findings}
                  go={setView} onScan={startScan} />
              )}
              {view === "devices" && (
                <Devices devices={devices} onOpen={open} scanning={scan.running} onScan={startScan} />
              )}
              {view === "device" && selected && (
                <DeviceDetail device={selected} rules={rules} loadDetail={loadDetail}
                  onBack={() => setView("devices")} onRename={renameDevice} onAccept={acceptFinding} />
              )}
              {view === "findings" && <Findings findings={findings} rules={rules} onAccept={acceptFinding} />}
              {view === "changes" && <Changes changes={changes} onAck={ackChange} />}
              {view === "map" && <MapView devices={devices} onOpen={open} />}
              {view === "settings" && <SettingsView caps={caps} iface={iface} cidr={cidr} rules={rules} />}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
