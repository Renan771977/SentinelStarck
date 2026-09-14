import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Radar, Server, Network, AlertTriangle, GitCompareArrows, Settings2,
  Search, Play, Square, ShieldAlert, ShieldCheck, Wifi, Router, Printer,
  Monitor, Camera, HardDrive, CircleHelp, ChevronRight, ChevronDown,
  Check, EyeOff, Clock, Lock, Unlock, Cable, Inbox, TerminalSquare, ArrowUpRight, Copy,
} from "lucide-react";
import { useSentinel, PHASE_LABEL } from "./lib/useSentinel";
import { useTerminal } from "./lib/useTerminal";
import TerminalPanel, { DeviceTerminalActions } from "./components/TerminalPanel";
import NetworkMap from "./components/NetworkMap";
import Dashboard from "./components/Dashboard";
import { ScanBanner } from "./components/ScanProgress";
import ErrorBoundary from "./components/ErrorBoundary";
import { useToast } from "./lib/toast";
import { useDialog } from "./lib/dialog";
import { useTheme } from "./lib/useTheme";
import { SkeletonDeviceList, SkeletonList, SkeletonDashboard } from "./components/Skeleton";
import { T, SEVERITY, SEVERITY_SOFT, SEVERITY_BY_RANK, sans, mono } from "./lib/theme";

/* ------------------------------------------------------------------ */
/*  Tokens                                                             */
/*  Espelham o tailwind.config.js. Cor vai em style inline porque o    */
/*  protótipo nasceu assim; migrar para classes Tailwind é opcional.   */
/* ------------------------------------------------------------------ */

const SEV = {
  critical: { label: "Crítica", color: SEVERITY.critical, rank: 0 },
  high: { label: "Alta", color: SEVERITY.high, rank: 1 },
  medium: { label: "Média", color: SEVERITY.medium, rank: 2 },
  low: { label: "Baixa", color: SEVERITY.low, rank: 3 },
  info: { label: "Info", color: SEVERITY.info, rank: 4 },
};
/** O backend manda `worstSeverityRank` como número. Este é o caminho inverso. */


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
    <section className="rounded-lg overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      {title && (
        <header className="flex items-center justify-between px-4 h-11" style={{ borderBottom: `1px solid ${T.borderSubtle}` }}>
          <h2 className="text-sm font-medium" style={{ ...sans, color: T.text }}>{title}</h2>
          {action}
        </header>
      )}
      <div className={pad ? "p-4" : ""}>{children}</div>
    </section>
  );
}

function SevDot({ sev, size = 8 }) {
  const s = SEVERITY[sev] || SEVERITY.info;
  return <span className="inline-block rounded-full shrink-0" style={{ width: size, height: size, background: s.color }} />;
}

function SevTag({ sev }) {
  const s = SEVERITY[sev] || SEVERITY.info;
  return (
    <span className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs"
      style={{ ...sans, color: s.color, background: `${s.color}18`, border: `1px solid ${s.color}33` }}>
      <SevDot sev={sev} size={6} />{s.label}
    </span>
  );
}

function ConfTag({ conf }) {
  const map = {
    confirmed: ["Confirmado", T.ok, Lock], likely: ["Provável", T.dim, Unlock],
    possible: ["Possível", T.faint, Unlock], high: ["Alta", T.ok, Lock],
    medium: ["Média", T.dim, Unlock], low: ["Baixa", T.faint, Unlock],
  };
  const [t, col, Icon] = map[conf] || map.possible;
  return <span className="inline-flex items-center gap-1 text-xs" style={{ ...sans, color: col }}><Icon size={11} />{t}</span>;
}

function Mono({ children, dim }) {
  return <span style={{ ...mono, color: dim ? T.dim : T.text, fontSize: 13 }}>{children}</span>;
}

/** Estado vazio. Aparece antes da primeira varredura, e é a primeira coisa
 *  que o usuário vê ao abrir o aplicativo: precisa dizer o que fazer. */
function Empty({ icon: Icon = Inbox, title, hint, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-16">
      <Icon size={28} style={{ color: T.faint }} />
      <p className="text-sm" style={{ ...sans, color: T.dim }}>{title}</p>
      {hint && <p className="text-xs text-center" style={{ ...sans, color: T.faint, maxWidth: 380 }}>{hint}</p>}
      {action}
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
              style={{ ...sans, background: T.accent, color: T.onAccent }}>Escanear rede</button>
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
          style={{ background: T.surface, border: `1px solid ${T.border}` }}>
          <Search size={14} style={{ color: T.faint }} />
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="Filtrar por nome, IP, MAC ou fabricante"
            className="bg-transparent outline-none flex-1 text-sm" style={{ ...sans, color: T.text }} />
        </div>
        <div className="flex gap-1 rounded-md p-1" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
          {kinds.map((k) => (
            <button key={k} onClick={() => setKind(k)} className="px-2.5 h-7 rounded text-xs"
              style={{ ...sans, background: kind === k ? T.raised : "transparent", color: kind === k ? T.text : T.faint }}>
              {k === "all" ? "Todos" : KIND_LABEL[k] || k}
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-lg overflow-hidden" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
        <div className="grid px-4 h-9 items-center text-xs"
          style={{ ...sans, color: T.faint, borderBottom: `1px solid ${T.borderSubtle}`, gridTemplateColumns: cols }}>
          <span>Dispositivo</span><span>Endereço</span><span>MAC</span>
          <span>Sistema</span><span>Portas</span><span>Achados</span><span>Visto</span>
        </div>

        {rows.map((d) => {
          const Icon = KIND_ICON[d.kind] || CircleHelp;
          const sev = d.worstSeverityRank !== null ? SEVERITY_BY_RANK[d.worstSeverityRank] : null;
          const offline = d.missCount > 0;
          return (
            <button key={d.id} onClick={() => onOpen(d)} data-row
              className={`w-full grid px-4 h-14 items-center text-left relative${
                d.justFound ? " anim-row-enter" : ""
              }`}
              style={{ borderBottom: `1px solid ${T.borderSubtle}`, gridTemplateColumns: cols }}>
              <span className="absolute left-0 top-0 bottom-0" style={{ width: 3, background: sev ? SEVERITY[sev] : "transparent" }} />
              <span className="flex items-center gap-2.5 min-w-0">
                <Icon size={15} style={{ color: offline ? T.faint : T.dim }} className="shrink-0" />
                <span className="min-w-0">
                  <span className="text-sm block truncate"
                    style={{ ...sans, color: d.label ? T.text : T.faint, fontStyle: d.label ? "normal" : "italic" }}>
                    {d.label || "sem nome"}
                  </span>
                  <span className="text-xs" style={{ ...sans, color: T.faint }}>{KIND_LABEL[d.kind] || d.kind}</span>
                </span>
              </span>
              <Mono>{d.ip || "—"}</Mono>
              <span className="min-w-0">
                <Mono dim>{d.mac || "—"}</Mono>
                <span className="text-xs block truncate" style={{ ...sans, color: T.faint }}>{d.vendor || ""}</span>
              </span>
              <span className="text-sm truncate" style={{ ...sans, color: T.dim }}>{d.osGuess || "—"}</span>
              <Mono dim>{d.openPorts}</Mono>
              <span>{sev ? <SevTag sev={sev} /> : <span className="text-xs" style={{ ...sans, color: T.faint }}>—</span>}</span>
              <span className="flex items-center gap-1.5">
                <span className="rounded-full" style={{ width: 6, height: 6, background: offline ? T.faint : T.ok }} />
                <span className="text-xs" style={{ ...sans, color: offline ? T.faint : T.dim }}>{ago(d.lastSeen)}</span>
              </span>
            </button>
          );
        })}

        {scanning && (
          <div className="flex items-center gap-2.5 px-4 h-14" style={{ color: T.accent }}>
            <Radar size={15} className="animate-spin" style={{ animationDuration: "2.5s" }} />
            <span className="text-sm" style={{ ...sans }}>Procurando mais dispositivos…</span>
          </div>
        )}
        {!scanning && rows.length === 0 && (
          <div className="px-4 py-12 text-center">
            <p className="text-sm" style={{ ...sans, color: T.dim }}>Nenhum dispositivo corresponde ao filtro.</p>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Detalhe                                                            */
/* ------------------------------------------------------------------ */
function DeviceDetail({ device, rules, loadDetail, onBack, onRename, onAccept, onOpenTerminal }) {
  const dialog = useDialog();
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
      <button onClick={onBack} className="flex items-center gap-1 text-sm self-start" style={{ ...sans, color: T.accent }}>
        <ChevronRight size={14} className="rotate-180" /> Dispositivos
      </button>

      <div className="rounded-lg p-5" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
        <div className="flex items-start gap-4">
          <div className="rounded-md p-2.5" style={{ background: T.raised }}>
            <Icon size={22} style={{ color: T.accent }} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3">
              <h1 style={{ ...sans, color: device.label ? T.text : T.faint, fontSize: 20, fontWeight: 600,
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
          <button onClick={async () => {
            const nome = await dialog.prompt({
              title: "Renomear dispositivo",
              label: "Nome do dispositivo",
              initial: device.label || "",
              placeholder: "ex.: Servidor de arquivos",
              confirmLabel: "Salvar",
            });
            if (nome) onRename(device.id, nome);
          }} className="rounded-md px-3 h-8 text-sm shrink-0"
            style={{ ...sans, color: T.text, background: T.raised, border: `1px solid ${T.border}` }}>
            Renomear
          </button>
        </div>
      </div>

      {onOpenTerminal && detail && (
        <Panel title="Conectar">
          {/* Só os serviços que a varredura realmente encontrou. Oferecer SSH
              num host sem a porta 22 é convidar o usuário a esperar timeout. */}
          <DeviceTerminalActions
            ip={device.ip}
            label={device.label}
            services={detail.services}
            onOpen={onOpenTerminal}
          />
        </Panel>
      )}

      <div className="flex gap-1">
        {["portas", "achados", "endereços"].map((t) => (
          <button key={t} onClick={() => setTab(t)} className="px-3 h-8 rounded-md text-sm"
            style={{ ...sans, background: tab === t ? T.surface : "transparent", color: tab === t ? T.text : T.faint,
              border: `1px solid ${tab === t ? T.border : "transparent"}` }}>
            {t[0].toUpperCase() + t.slice(1)}
            {t === "achados" && detail?.findings.length > 0 && (
              <span className="ml-1.5" style={{ ...mono, color: SEVERITY.high }}>{detail.findings.length}</span>
            )}
          </button>
        ))}
      </div>

      {err && <Panel><p className="text-sm" style={{ ...sans, color: SEVERITY.high }}>{err}</p></Panel>}
      {!detail && !err && <SkeletonList rows={5} />}

      {detail && tab === "portas" && (
        <Panel pad={false}>
          {detail.services.length === 0 ? (
            <Empty title="Nenhuma porta aberta encontrada"
              hint="Ou o dispositivo não expõe serviço, ou a varredura rodou em perfil de presença." />
          ) : (
            <>
              <div className="grid px-4 h-9 items-center text-xs"
                style={{ ...sans, color: T.faint, borderBottom: `1px solid ${T.borderSubtle}`, gridTemplateColumns: ".4fr .6fr 2fr" }}>
                <span>Porta</span><span>Serviço</span><span>Banner</span>
              </div>
              {detail.services.map((p) => (
                <ServiceRow key={`${p.protocol}/${p.port}`} svc={p} ip={device.ip} onOpenTerminal={onOpenTerminal} />
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
                <ShieldCheck size={18} style={{ color: T.ok }} />
                <span className="text-sm" style={{ ...sans, color: T.dim }}>Nenhum problema encontrado neste dispositivo.</span>
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
            style={{ ...sans, color: T.faint, borderBottom: `1px solid ${T.borderSubtle}`, gridTemplateColumns: ".4fr 1fr .6fr" }}>
            <span>Tipo</span><span>Valor</span><span>Situação</span>
          </div>
          {detail.addresses.map((a, i) => (
            <div key={i} className="grid px-4 h-11 items-center"
              style={{ borderBottom: `1px solid ${T.borderSubtle}`, gridTemplateColumns: ".4fr 1fr .6fr" }}>
              <span className="text-sm" style={{ ...sans, color: T.dim }}>{a.kind.toUpperCase()}</span>
              <Mono>{a.value}</Mono>
              <span className="text-xs" style={{ ...sans, color: a.isCurrent ? T.ok : T.faint }}>
                {a.isCurrent ? "atual" : "histórico"}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-3 px-4 h-14">
            <Clock size={13} style={{ color: T.faint }} />
            <span className="text-sm" style={{ ...sans, color: T.faint }}>
              Visto pela primeira vez em {dateOf(detail.firstSeen)}
            </span>
          </div>
        </Panel>
      )}
    </div>
  );
}

/** Uma porta na tabela de detalhe. Expande certificado TLS quando há, e
 *  oferece abrir no navegador quando é serviço web. */
/** Um botão de conexão. Ação depende do tipo: navegador abre a URL, os
 *  demais copiam o comando para a área de transferência. */
function ConnectButton({ hint, ip, onOpenTerminal }) {
  const [copied, setCopied] = useState(false);
  const warn = !!hint.warning;

  // SSH e Telnet abrem uma SESSÃO dedicada (o processo ssh roda direto). Os
  // demais shells abrem um PowerShell com o comando já digitado, para a pessoa
  // conferir antes de executar.
  const canOpenSession =
    hint.kind === "shell" && onOpenTerminal &&
    (hint.command.startsWith("ssh ") || hint.command.startsWith("telnet "));

  const act = () => {
    if (hint.kind === "browser") {
      invoke("open_external", { url: hint.command }).catch(() => {});
      return;
    }
    if (canOpenSession) {
      const isSsh = hint.command.startsWith("ssh ");
      onOpenTerminal({ kind: isSsh ? "ssh" : "telnet", host: ip, label: ip });
      return;
    }
    // Demais clientes (mysql, redis-cli, smbclient): abre um shell e DIGITA o
    // comando sem executar. A pessoa confere e aperta Enter. Um clique em vez
    // de copiar-navegar-colar, sem perder o controle de rodar às cegas.
    if (onOpenTerminal) {
      onOpenTerminal({ kind: "shell", label: `${hint.label} · ${ip}`, prefill: hint.command });
      return;
    }
    // Sem terminal disponível (build sem a feature): cai para copiar.
    navigator.clipboard?.writeText(hint.command).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    }).catch(() => {});
  };

  const color = warn ? SEVERITY.medium : T.accent;
  return (
    <button onClick={act} title={hint.warning || hint.command}
      className="text-xs rounded px-2 h-6 inline-flex items-center gap-1"
      style={{ ...sans, color, background: `${color}12`, border: `1px solid ${color}33` }}>
      {hint.kind === "browser"
        ? <>{hint.label} <ArrowUpRight size={11} /></>
        : (canOpenSession || onOpenTerminal)
          ? <>{hint.label} <TerminalSquare size={11} /></>
          : copied ? <>Copiado <Check size={11} /></> : <>{hint.label} <Copy size={11} /></>}
    </button>
  );
}

function ServiceRow({ svc, ip, onOpenTerminal }) {
  const [open, setOpen] = useState(false);
  const tls = svc.tlsInfo ? JSON.parse(svc.tlsInfo) : null;

  return (
    <div style={{ borderBottom: `1px solid ${T.borderSubtle}` }}>
      <div data-row className="grid px-4 py-2 items-center"
        style={{ gridTemplateColumns: ".4fr .6fr 1.4fr auto" }}>
        <Mono>{svc.port}</Mono>
        <span className="text-sm flex items-center gap-1.5" style={{ ...sans, color: T.dim }}>
          {svc.serviceName || svc.protocol}
          {tls && (
            <button onClick={() => setOpen(!open)} title="Ver certificado"
              style={{ color: tls.selfSigned ? SEVERITY.medium : T.ok }}>
              <Lock size={11} />
            </button>
          )}
        </span>
        <Mono dim>{(svc.banner || (tls ? tls.protocol : "—")).split("\n")[0]}</Mono>
        <span className="flex justify-end gap-1.5 flex-wrap">
          {(svc.connectHints || []).map((h, i) => (
            <ConnectButton key={i} hint={h} ip={ip} onOpenTerminal={onOpenTerminal} />
          ))}
        </span>
      </div>

      {open && tls && (
        <div className="px-4 pb-3 pt-1 grid gap-y-1.5"
          style={{ gridTemplateColumns: "auto 1fr", columnGap: 24, paddingLeft: 24 }}>
          <CertField label="Protocolo" value={tls.protocol} />
          <CertField label="Emissor" value={tls.issuer} m />
          <CertField label="Sujeito" value={tls.subject} m />
          {tls.san?.length > 0 && <CertField label="Nomes (SAN)" value={tls.san.join(", ")} m />}
          <CertField label="Chave" value={tls.keyType ? `${tls.keyType} ${tls.keyBits || ""} bits` : "—"} />
          <CertField label="Válido até" value={dateOf(tls.notAfter)} />
          <CertField label="Autoassinado" value={tls.selfSigned ? "sim" : "não"} />
        </div>
      )}
    </div>
  );
}

function CertField({ label, value, m }) {
  return (
    <>
      <span className="text-xs" style={{ ...sans, color: T.faint }}>{label}</span>
      <span className="text-xs truncate" style={{ ...(m ? mono : sans), color: T.dim }}>{value || "—"}</span>
    </>
  );
}

function Field({ label, value, sans: isSans }) {
  return (
    <span>
      <span className="text-xs block" style={{ ...sans, color: T.faint }}>{label}</span>
      <span style={{ ...(isSans ? sans : mono), color: T.text, fontSize: 13 }}>{value}</span>
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Achados                                                            */
/* ------------------------------------------------------------------ */
function FindingCard({ finding, rule, affected, onAccept }) {
  const dialog = useDialog();
  const [open, setOpen] = useState(false);
  // Regra ausente do catálogo indica versão de banco mais nova que o binário.
  // Degrada mostrando o id em vez de quebrar a tela.
  const r = rule || { title: finding?.ruleId || "Regra desconhecida", why: "", fix: "" };
  const sev = finding?.severity || r.severity || "info";

  return (
    <div className={`rounded-lg overflow-hidden${sev === "critical" ? " anim-attention" : ""}`}
      style={{ background: T.surface, border: `1px solid ${T.border}` }}>
      <div className="flex">
        <span style={{ width: 3, background: SEVERITY[sev] }} />
        <button onClick={() => setOpen(!open)} className="flex-1 flex items-center gap-3 px-4 py-3 text-left">
          {open ? <ChevronDown size={14} style={{ color: T.faint }} /> : <ChevronRight size={14} style={{ color: T.faint }} />}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2.5">
              <span className="text-sm font-medium" style={{ ...sans, color: T.text }}>{r.title}</span>
              <Mono dim>{finding?.ruleId}</Mono>
            </div>
            {affected && (
              <p className="text-xs mt-1" style={{ ...sans, color: T.faint }}>
                {affected.length} dispositivo{affected.length > 1 ? "s" : ""} afetado{affected.length > 1 ? "s" : ""}
              </p>
            )}
            {!affected && finding?.evidence && (
              <p className="text-xs mt-1 truncate" style={{ ...mono, color: T.faint }}>{finding.evidence}</p>
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
              <p className="text-xs mb-1.5" style={{ ...sans, color: T.faint }}>Por que isso importa</p>
              <p className="text-sm leading-relaxed" style={{ ...sans, color: T.dim, maxWidth: "72ch" }}>{r.why}</p>
            </div>
          )}
          {r.fix && (
            <div>
              <p className="text-xs mb-1.5" style={{ ...sans, color: T.faint }}>Como corrigir</p>
              <p className="text-sm leading-relaxed" style={{ ...sans, color: T.dim, maxWidth: "72ch" }}>{r.fix}</p>
            </div>
          )}
          {affected && (
            <div>
              <p className="text-xs mb-1.5" style={{ ...sans, color: T.faint }}>Afetados</p>
              <div className="flex flex-wrap gap-2">
                {affected.map((f) => (
                  <span key={f.id} className="rounded px-2 py-1 text-xs"
                    style={{ ...mono, background: T.raised, color: T.dim, border: `1px solid ${T.border}` }}>
                    {f.deviceIp || f.deviceId.slice(0, 8)}{f.scope ? ` · ${f.scope}` : ""}
                  </span>
                ))}
              </div>
            </div>
          )}
          {onAccept && finding && (
            <div className="flex gap-2">
              <button onClick={async () => {
                const motivo = await dialog.prompt({
                  title: "Aceitar risco",
                  label: "Justificativa (fica registrada na auditoria)",
                  placeholder: "ex.: switch legado, troca no orçamento de 2027",
                  multiline: true,
                  required: true,
                  confirmLabel: "Aceitar risco",
                });
                if (motivo) onAccept(finding.id, motivo);
              }} className="inline-flex items-center gap-1.5 rounded-md px-2.5 h-8 text-sm"
                style={{ ...sans, background: T.raised, color: T.dim, border: `1px solid ${T.border}` }}>
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
    (a, b) => SEVERITY[byRule[a][0].severity].rank - SEVERITY[byRule[b][0].severity].rank,
  );

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm" style={{ ...sans, color: T.dim }}>
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
        <p className="text-sm" style={{ ...sans, color: T.dim }}>
          Comparação com o estado da varredura anterior.
        </p>
        <button onClick={() => setShowAck(!showAck)} className="text-sm" style={{ ...sans, color: T.accent }}>
          {showAck ? "Ocultar já vistas" : "Mostrar já vistas"}
        </button>
      </div>
      <Panel pad={false}>
        {rows.map((c) => (
          <div key={c.id} data-row className="flex items-center gap-3 px-4 h-16 relative"
            style={{ borderBottom: `1px solid ${T.borderSubtle}`, opacity: c.acknowledged ? 0.5 : 1 }}>
            <span className="absolute left-0 top-0 bottom-0"
              style={{ width: 3, background: c.acknowledged ? "transparent" : SEVERITY[c.severity] }} />
            <SevDot sev={c.severity} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm" style={{ ...sans, color: T.text }}>{CHANGE_LABEL[c.changeType] || c.changeType}</span>
                <Mono dim>{c.deviceIp || c.deviceLabel || ""}</Mono>
              </div>
              <p className="text-xs mt-0.5 truncate" style={{ ...mono, color: T.faint }}>
                {c.before ? `${c.before} → ${c.after || "—"}` : c.after || ""}
              </p>
            </div>
            <span className="text-xs shrink-0" style={{ ...sans, color: T.faint }}>{ago(c.detectedAt)}</span>
            {!c.acknowledged && (
              <button onClick={() => onAck(c.id)} className="rounded-md px-2.5 h-7 text-xs shrink-0"
                style={{ ...sans, background: T.raised, color: T.dim, border: `1px solid ${T.border}` }}>
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
/*  Configurações                                                      */
/* ------------------------------------------------------------------ */
/** Confirmação do export, com o selo em destaque para copiar. */
function ExportResult({ data, onClose }) {
  const [copied, setCopied] = useState(false);
  const err = data.error;

  return (
    <div className="absolute inset-0 z-20 flex items-center justify-center"
      style={{ background: T.overlay }} onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()}
        className="rounded-lg p-5" style={{ background: T.surface, border: `1px solid ${T.border}`, width: 560 }}>
        {err ? (
          <>
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={18} style={{ color: SEVERITY.critical }} />
              <span className="text-sm font-medium" style={{ ...sans, color: T.text }}>Falha ao exportar</span>
            </div>
            <p className="text-sm" style={{ ...sans, color: T.dim }}>{err}</p>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2 mb-3">
              <ShieldCheck size={18} style={{ color: T.ok }} />
              <span className="text-sm font-medium" style={{ ...sans, color: T.text }}>Evidência exportada</span>
            </div>
            <p className="text-sm mb-3" style={{ ...sans, color: T.dim }}>
              {data.deviceCount} dispositivos e {data.findingCount} achados, com selo de integridade.
            </p>
            <div className="rounded-md p-3 mb-3" style={{ background: T.raised, border: `1px solid ${T.border}` }}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs" style={{ ...sans, color: T.faint }}>Selo SHA-256 do manifesto</span>
                <button onClick={() => {
                  navigator.clipboard?.writeText(data.hash);
                  setCopied(true); window.setTimeout(() => setCopied(false), 1400);
                }} className="text-xs inline-flex items-center gap-1" style={{ ...sans, color: T.accent }}>
                  {copied ? <>Copiado <Check size={11} /></> : <>Copiar <Copy size={11} /></>}
                </button>
              </div>
              <p style={{ ...mono, color: T.ok, fontSize: 11, wordBreak: "break-all" }}>{data.hash}</p>
            </div>
            <div className="flex flex-col gap-1 text-xs" style={{ ...mono, color: T.faint }}>
              <span>{data.manifestPath}</span>
              <span>{data.reportPath}</span>
            </div>
            <p className="text-xs mt-3 leading-relaxed" style={{ ...sans, color: T.faint, maxWidth: "64ch" }}>
              O arquivo .json é a evidência verificável; qualquer alteração muda o selo. O .html é o
              relatório legível — abra no navegador e use Imprimir para gerar um PDF.
            </p>
          </>
        )}
        <div className="flex justify-end mt-4">
          <button onClick={onClose} className="rounded-md px-3 h-8 text-sm"
            style={{ ...sans, background: T.raised, color: T.text, border: `1px solid ${T.border}` }}>
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
}

/** Seletor de tema, com amostra da paleta de cada um. */
function ThemePicker() {
  const { theme, setTheme, themes } = useTheme();

  return (
    <Panel title="Aparência">
      <div className="grid grid-cols-2 gap-2">
        {themes.map((t) => {
          const ativo = t.id === theme;
          return (
            <button key={t.id} onClick={() => setTheme(t.id)}
              className="flex items-start gap-3 rounded-md p-3 text-left"
              style={{
                background: ativo ? T.raised : "transparent",
                border: `1px solid ${ativo ? T.accent : T.border}`,
              }}>
              {/* Amostra: fundo, destaque, secundária e sucesso. Quatro cores
                  bastam para reconhecer a paleta sem aplicá-la. */}
              <span className="flex rounded overflow-hidden shrink-0"
                style={{ border: `1px solid ${T.border}`, marginTop: 2 }}>
                {t.swatch.map((c, i) => (
                  <span key={i} style={{ width: 12, height: 32, background: c }} />
                ))}
              </span>
              <span className="min-w-0 flex-1">
                <span className="text-sm block flex items-center gap-1.5"
                  style={{ ...sans, color: T.text }}>
                  {t.name}
                  {ativo && <Check size={12} style={{ color: T.accent }} />}
                </span>
                <span className="text-xs block mt-0.5" style={{ ...sans, color: T.faint }}>
                  {t.description}
                </span>
              </span>
            </button>
          );
        })}
      </div>
      <p className="text-sm leading-relaxed mt-3" style={{ ...sans, color: T.faint, maxWidth: "70ch" }}>
        A escolha é salva no banco do aplicativo e sobrevive a reinício. O terminal e os
        gráficos mudam junto.
      </p>
    </Panel>
  );
}

function SettingsView({ caps, iface, cidr, rules, interfaces, onRecheck, onSelect }) {
  const total = Object.keys(rules).length;
  const off = Object.values(rules).filter((r) => !r.enabled).length;

  // Grade de duas colunas: a interface e as permissões lado a lado, catálogo e
  // segurança abaixo. Preenche a largura em vez de deixar um vão preto à
  // direita, e mantém as linhas curtas o suficiente para leitura.
  return (
    <div className="grid grid-cols-2 gap-4 items-start" style={{ maxWidth: 1100 }}>
      <div className="col-span-2">
        <ThemePicker />
      </div>

      <div className="col-span-2">
      <Panel title="Interfaces de rede">
        <div className="flex flex-col gap-1">
          {(interfaces || []).filter((i) => !i.isLoopback).map((i) => (
            <button key={i.name} onClick={() => onSelect?.(i.name)}
              className="flex items-center gap-3 px-2 h-11 rounded-md text-left"
              style={{ background: i.name === iface ? T.raised : "transparent" }}>
              <span className="rounded-full shrink-0"
                style={{ width: 7, height: 7, background: i.arpCapable ? T.ok : SEVERITY.medium }} />
              <span className="flex-1 min-w-0">
                <span className="text-sm block truncate" style={{ ...sans, color: T.text }}>{i.name}</span>
                <span className="text-xs" style={{ ...mono, color: T.faint }}>
                  {i.address || "sem IPv4"}
                </span>
              </span>
              <span className="text-xs shrink-0" style={{ ...sans, color: i.arpCapable ? T.ok : SEVERITY.medium }}>
                {i.arpCapable ? "ARP disponível" : "sem ARP"}
              </span>
              {i.name === iface && (
                <span className="text-xs shrink-0" style={{ ...sans, color: T.accent }}>em uso</span>
              )}
            </button>
          ))}
          <div className="pt-2">
            <Row label="Faixa a varrer" value={cidr || "—"} />
          </div>
          <p className="text-sm leading-relaxed pt-1" style={{ ...sans, color: T.faint, maxWidth: "70ch" }}>
            Adaptador virtual de VirtualBox, Hyper-V ou WSL aparece nesta lista mas não
            tem canal de enlace, então nunca vai oferecer ARP. Escolha a placa física
            ligada à rede que você quer auditar.
          </p>
          <p className="text-sm leading-relaxed" style={{ ...sans, color: T.faint, maxWidth: "70ch" }}>
            O sensor enxerga apenas a VLAN onde está conectado. Outras VLANs precisam de
            uma instância própria ou de leitura via SNMP no roteador.
          </p>
        </div>
      </Panel>
      </div>

      <Panel title="Permissões do sistema"
        action={
          <button onClick={onRecheck} className="text-xs" style={{ ...sans, color: T.accent }}>
            Verificar novamente
          </button>
        }>
        <div className="flex flex-col gap-3">
          <Capability on name="Varredura de portas TCP" note="Não exige privilégio" />
          <Capability on={caps?.arpActive} name="Varredura ARP ativa"
            note="Exige Npcap no Windows, CAP_NET_RAW no Linux" />
          <Capability on={caps?.passiveListen} name="Escuta passiva de broadcast"
            note="Mesma exigência do ARP" />
          {caps?.arpActive && (
            <div className="rounded-md p-3 flex gap-2.5 mt-1"
              style={{ background: `${T.ok}12`, border: `1px solid ${T.ok}33` }}>
              <ShieldCheck size={15} style={{ color: T.ok }} className="mt-0.5 shrink-0" />
              <p className="text-sm leading-relaxed" style={{ ...sans, color: T.dim, maxWidth: "68ch" }}>
                Modo completo. A varredura ARP encontra todo dispositivo da rede local,
                inclusive os que bloqueiam ping e mantêm todas as portas fechadas.
              </p>
            </div>
          )}
          {caps?.reason && (
            <div className="rounded-md p-3 flex gap-2.5 mt-1"
              style={{ background: `${SEVERITY.medium}12`, border: `1px solid ${SEVERITY.medium}33` }}>
              <AlertTriangle size={15} style={{ color: SEVERITY.medium }} className="mt-0.5 shrink-0" />
              <p className="text-sm leading-relaxed" style={{ ...sans, color: T.dim, maxWidth: "68ch" }}>{caps.reason}</p>
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Catálogo de regras">
        <div className="flex flex-col gap-3">
          <Row label="Regras carregadas" value={String(total)} />
          <Row label="Desligadas por padrão" value={String(off)} />
          <p className="text-sm leading-relaxed pt-1" style={{ ...sans, color: T.faint, maxWidth: "70ch" }}>
            As regras desligadas testam credencial padrão. Elas tentam autenticar, o que pode
            bloquear conta em sistema com política de lockout, e por isso exigem consentimento
            explícito por dispositivo.
          </p>
        </div>
      </Panel>

      <Panel title="Segurança da varredura">
        <div className="rounded-md p-3 flex gap-2.5"
          style={{ background: `${SEVERITY.medium}12`, border: `1px solid ${SEVERITY.medium}33` }}>
          <AlertTriangle size={15} style={{ color: SEVERITY.medium }} className="mt-0.5 shrink-0" />
          <p className="text-sm leading-relaxed" style={{ ...sans, color: T.dim, maxWidth: "68ch" }}>
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
      <span className="text-sm" style={{ ...sans, color: T.dim }}>{label}</span>
      <Mono>{value}</Mono>
    </div>
  );
}

function Capability({ on, name, note }) {
  return (
    <div className="flex items-center gap-2.5 h-8">
      <span className="rounded-full shrink-0" style={{ width: 7, height: 7, background: on ? T.ok : T.faint }} />
      <span className="text-sm" style={{ ...sans, color: on ? T.text : T.faint }}>{name}</span>
      <span className="text-xs" style={{ ...sans, color: T.faint }}>· {note}</span>
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
  { id: "terminal", label: "Terminal", icon: TerminalSquare, needsTerminal: true },
  { id: "settings", label: "Configurações", icon: Settings2 },
];

export default function App() {
  const {
    iface, cidr, caps, devices, changes, findings, rules, loading, scan,
    startScan, cancelScan, ackChange, renameDevice, loadDetail, acceptFinding,
    recheckCaps, selectInterface, interfaces, unseenChanges,
  } = useSentinel();

  const term = useTerminal();
  const toast = useToast();

  const [view, setView] = useState("overview");
  const [selected, setSelected] = useState(null);
  const [exportState, setExportState] = useState(null); // null | "working" | result

  const open = (d) => { setSelected(d); setView("device"); };

  // Avisa quando a varredura falha, além do texto na barra.
  const prevError = useRef(null);
  useEffect(() => {
    if (scan.error && scan.error !== prevError.current) {
      toast.error(`Falha na varredura: ${scan.error}`);
    }
    prevError.current = scan.error;
  }, [scan.error, toast]);

  const doExport = async () => {
    if (devices.length === 0) return;
    setExportState("working");
    try {
      const r = await api.exportEvidence(cidr || "rede local");
      setExportState(r);
      toast.success("Evidência exportada com selo de integridade.");
    } catch (e) {
      // Cancelar o diálogo cai aqui; não é erro que mereça alarde.
      if (String(e).includes("cancelada")) {
        setExportState(null);
      } else {
        setExportState({ error: String(e) });
        toast.error("Não foi possível exportar a evidência.");
      }
    }
  };

  // Wrappers com feedback: a ação continua no hook, o toast confirma que
  // aconteceu. Sem isto, renomear e aceitar acontecem em silêncio e parecem
  // não ter funcionado.
  const renameWithToast = async (id, name) => {
    try {
      await renameDevice(id, name);
      toast.success(`Dispositivo renomeado para "${name}".`);
    } catch {
      toast.error("Não foi possível renomear o dispositivo.");
    }
  };

  const acceptWithToast = async (id, reason) => {
    try {
      await acceptFinding(id, reason);
      toast.success("Risco aceito e registrado.");
    } catch {
      toast.error("Não foi possível aceitar o risco.");
    }
  };

  const ackWithToast = async (id) => {
    try {
      await ackChange(id);
    } catch {
      toast.error("Não foi possível marcar como vista.");
    }
  };

  return (
    <div className="flex" style={{ background: T.bg, color: T.text, minHeight: "100vh", ...sans }}>
      <nav className="w-52 shrink-0 flex flex-col" style={{ background: T.surface, borderRight: `1px solid ${T.border}` }}>
        <div className="h-14 flex items-center gap-2.5 px-4" style={{ borderBottom: `1px solid ${T.border}` }}>
          <span className="rounded flex items-center justify-center"
            style={{ width: 24, height: 24, background: `linear-gradient(135deg, ${T.accent}, ${T.accent2})` }}>
            <Radar size={14} color={T.onAccent} />
          </span>
          <span style={{ fontSize: 14, fontWeight: 600, letterSpacing: "-0.01em" }}>SentinelStack</span>
        </div>

        <div className="flex flex-col gap-0.5 p-2">
          {NAV.filter((n) => !n.needsTerminal || term.available).map((n) => {
            const active = view === n.id || (view === "device" && n.id === "devices");
            return (
              <button key={n.id} onClick={() => { setView(n.id); setSelected(null); }}
                className="flex items-center gap-2.5 h-9 px-2.5 rounded-md text-sm relative"
                style={{ background: active ? T.raised : "transparent", color: active ? T.text : T.dim }}>
                {active && <span className="absolute left-0 rounded-r" style={{ width: 2, height: 16, background: T.accent }} />}
                <n.icon size={15} style={{ color: active ? T.accent : T.faint }} />
                {n.label}
                {n.id === "changes" && unseenChanges > 0 && (
                  <span className="ml-auto rounded px-1.5 text-xs"
                    style={{ ...mono, background: `${T.accent2}2A`, color: T.accent2 }}>{unseenChanges}</span>
                )}
                {n.id === "findings" && findings.length > 0 && (
                  <span className="ml-auto rounded px-1.5 text-xs"
                    style={{ ...mono, background: `${SEVERITY.high}2A`, color: SEVERITY.high }}>{findings.length}</span>
                )}
                {n.id === "terminal" && term.sessions.length > 0 && (
                  <span className="ml-auto rounded px-1.5 text-xs"
                    style={{ ...mono, background: `${T.accent}22`, color: T.accent }}>{term.sessions.length}</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Só aparece quando há algo a resolver.
            Um aviso permanente dizendo "está tudo bem" é ruído: some da
            atenção em dois dias e deixa de funcionar como aviso no dia em que
            realmente houver problema. Em modo completo, o estado fica visível
            em Configurações, que é onde se vai procurar por ele. */}
        {caps && !caps.arpActive && (
          <div className="mt-auto p-3">
            <div className="rounded-md p-2.5" style={{ background: T.raised, border: `1px solid ${SEVERITY.medium}44` }}>
              <div className="flex items-center gap-1.5">
                <Unlock size={11} style={{ color: SEVERITY.medium }} />
                <span className="text-xs" style={{ color: SEVERITY.medium }}>Modo limitado</span>
              </div>
              <p className="text-xs mt-1 leading-snug" style={{ color: T.faint }}>
                {caps.reason || "Apenas varredura TCP."}
              </p>
              <button onClick={recheckCaps} className="text-xs mt-2" style={{ color: T.accent }}>
                Verificar novamente
              </button>
            </div>
          </div>
        )}
      </nav>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 shrink-0 flex items-center gap-4 px-6"
          style={{ borderBottom: `1px solid ${T.border}`, background: T.surface }}>
          {/* Seletor, não rótulo. Máquina com VirtualBox, Hyper-V ou WSL tem
              várias interfaces, e só uma delas é a rede que se quer varrer.
              O aviso ao lado de cada uma diz qual consegue ARP. */}
          <select
            value={iface || ""}
            onChange={(e) => selectInterface(e.target.value)}
            disabled={scan.running}
            className="rounded-md px-2 h-8 text-sm outline-none"
            style={{
              ...mono, fontSize: 13,
              background: T.raised, color: T.text,
              border: `1px solid ${T.border}`,
              opacity: scan.running ? 0.5 : 1,
            }}>
            {interfaces.length === 0 && <option value="">sem interface</option>}
            {interfaces.filter((i) => !i.isLoopback).map((i) => (
              <option key={i.name} value={i.name} style={{ background: T.surface }}>
                {i.name} · {i.network || "sem IPv4"}{i.arpCapable ? "" : "  (sem ARP)"}
              </option>
            ))}
          </select>
          <span className="text-xs" style={{ color: T.faint }}>
            {scan.running
              ? `${PHASE_LABEL[scan.phase] || "Varrendo"}… ${scan.percent}%`
              : scan.lastResult
                ? `${scan.lastResult.found} dispositivos · ${scan.lastResult.new} novos`
                : "Nenhuma varredura nesta sessão"}
          </span>
          {scan.error && <span className="text-xs" style={{ color: SEVERITY.critical }}>{scan.error}</span>}

          {/* Espaçador: empurra os botões para a direita SEMPRE, mesmo quando o
              botão de exportar não aparece (nenhum dispositivo ainda). Sem ele,
              o escanear escorregava para o meio da barra. */}
          <span className="flex-1" />

          {devices.length > 0 && (
            <button onClick={doExport} disabled={exportState === "working"}
              className="inline-flex items-center gap-1.5 rounded-md px-3 h-9 text-sm"
              style={{
                ...sans, background: "transparent", color: T.dim,
                border: `1px solid ${T.border}`,
              }}
              title="Exportar evidência selada (.json + .html)">
              <ShieldCheck size={14} />
              {exportState === "working" ? "Exportando…" : "Exportar evidência"}
            </button>
          )}
          <button onClick={scan.running ? cancelScan : () => startScan()}
            disabled={!iface || !cidr}
            className="inline-flex items-center gap-2 rounded-md px-3.5 h-9 text-sm font-medium"
            style={{
              background: scan.running ? T.raised : T.accent,
              color: scan.running ? T.text : T.onAccent,
              border: `1px solid ${scan.running ? T.border : T.accent}`,
              opacity: !iface || !cidr ? 0.5 : 1,
            }}>
            {scan.running ? <><Square size={13} /> Parar</> : <><Play size={13} /> Escanear rede</>}
          </button>
        </header>

        {scan.running && (
          <div style={{ height: 2, background: T.raised }}>
            <div style={{ height: "100%", width: `${scan.percent}%`, background: T.accent, transition: "width .35s linear" }} />
          </div>
        )}

        {/* O terminal fica MONTADO o tempo todo, só oculto.
            Desmontar destruiria as instâncias do xterm e o histórico da tela
            iria embora, enquanto a sessão continuaria viva no Rust: ao voltar,
            um terminal em branco com só o cursor, porque o shell não reimprime
            um prompt que já imprimiu. */}
        <div className="flex-1 min-h-0 relative">
          {exportState && typeof exportState === "object" && (
          <ExportResult data={exportState} onClose={() => setExportState(null)} />
        )}

        <main className="absolute inset-0 p-6"
            style={{
              display: view === "terminal" ? "none" : "block",
              // O mapa gerencia o próprio deslocamento com zoom e arrasto;
              // rolagem do container brigaria com ele.
              overflow: view === "map" ? "hidden" : "auto",
            }}>
          {/* Banner de varredura em andamento, presente em toda tela menos a
              Visão geral (lá o próprio dashboard já mostra o progresso). Assim
              a varredura nunca é uma caixa preta, mesmo navegando para outra
              aba no meio dela. */}
          {scan.running && view !== "overview" && view !== "device" && (
            <ScanBanner phase={scan.phase} percent={scan.percent} />
          )}

          {loading ? (
            view === "devices" ? <SkeletonDeviceList /> : <SkeletonDashboard />
          ) : (
            <ErrorBoundary scope="esta tela" resetKey={view}>
            {/* `key={view}` faz o React remontar ao trocar de aba, o que
                dispara a animação de entrada. Sem a key, o conteúdo trocaria
                sem transição e a mudança de contexto ficaria abrupta. */}
            {/* `h-full` é obrigatório aqui: o Mapa e o Terminal usam h-full
                internamente, e sem altura no wrapper eles colapsam para zero.
                `key={view}` dispara a animação de entrada ao trocar de aba. */}
            <div key={view} className="anim-view-enter h-full">
              {view === "overview" && (
                <Dashboard devices={devices} changes={changes} findings={findings}
                  scan={scan} go={setView} onScan={startScan} />
              )}
              {view === "devices" && (
                <Devices devices={devices} onOpen={open} scanning={scan.running} onScan={startScan} />
              )}
              {view === "device" && selected && (
                <DeviceDetail device={selected} rules={rules} loadDetail={loadDetail}
                  onBack={() => setView("devices")} onRename={renameWithToast} onAccept={acceptWithToast}
                  onOpenTerminal={term.available
                    ? async (spec) => { await term.openSession(spec); setView("terminal"); }
                    : null} />
              )}
              {view === "findings" && <Findings findings={findings} rules={rules} onAccept={acceptWithToast} />}
              {view === "changes" && <Changes changes={changes} onAck={ackWithToast} />}
              {view === "map" && (
                devices.length === 0
                  ? <Panel><Empty icon={Network} title="Sem dados para desenhar o mapa"
                      hint="Rode uma varredura para montar a topologia." /></Panel>
                  : <div className="h-full"><NetworkMap devices={devices} cidr={cidr} onOpen={open} /></div>
              )}
              {view === "settings" && (
                <SettingsView caps={caps} iface={iface} cidr={cidr} rules={rules}
                  interfaces={interfaces} onRecheck={recheckCaps} onSelect={selectInterface} />
              )}
            </div>
            </ErrorBoundary>
          )}
          </main>

          {term.available && (
            <div className="absolute inset-0 flex flex-col"
              style={{ display: view === "terminal" ? "flex" : "none" }}>
              {term.error && (
                <div className="flex items-center gap-2 px-3 py-2 shrink-0"
                  style={{ background: SEVERITY_SOFT.critical, borderBottom: `1px solid ${SEVERITY.critical}` }}>
                  <AlertTriangle size={14} style={{ color: SEVERITY.critical }} className="shrink-0" />
                  <span className="text-xs flex-1" style={{ ...sans, color: T.dim }}>{term.error}</span>
                  <button onClick={term.clearError} className="text-xs" style={{ ...sans, color: T.faint }}>
                    fechar
                  </button>
                </div>
              )}
              <div className="flex-1 min-h-0">
                <TerminalPanel
                  sessions={term.sessions}
                  onOpen={term.openSession}
                  onClose={term.closeSession}
                  visible={view === "terminal"}
                />
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}