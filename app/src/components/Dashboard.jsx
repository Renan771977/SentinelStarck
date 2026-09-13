import { Activity, Wifi, WifiOff, TrendingUp, TrendingDown, Minus,
  ShieldAlert, ShieldCheck, GitCompareArrows, Server, AlertTriangle,
  ArrowUpRight, Gauge } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import LatencyChart from "./LatencyChart";
import ScanningState from "./ScanProgress";
import { useTelemetry } from "../lib/useTelemetry";

const C = {
  bg: "#090C12", panel: "#0F141D", raised: "#161D29", line: "#222C3C",
  lineSoft: "#19212E", text: "#E8ECF4", dim: "#9AA5B8", faint: "#6B7688",
  cyan: "#00C2FF", purple: "#7C3AED", ok: "#35D07F",
};
const SEV = {
  critical: "#FF4D6D", high: "#FF8A3D", medium: "#FFC94D", low: "#4DA8FF", info: "#7D8899",
};
const sans = { fontFamily: "Inter,-apple-system,'Segoe UI',sans-serif" };
const mono = { fontFamily: "'JetBrains Mono','SFMono-Regular',Consolas,monospace" };
const BY_RANK = ["critical", "high", "medium", "low", "info"];
const CHANGE_LABEL = {
  device_new: "Dispositivo novo", device_gone: "Dispositivo ausente",
  device_returned: "Dispositivo voltou", port_opened: "Porta aberta",
  port_closed: "Porta fechada", ip_changed: "IP alterado",
  mac_changed: "MAC alterado", hostname_changed: "Nome alterado",
  vendor_conflict: "Fabricante divergente", os_changed: "Sistema alterado",
};

function ago(epoch) {
  if (!epoch) return "—";
  const s = Math.floor(Date.now() / 1000) - epoch;
  if (s < 90) return "agora";
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  if (s < 86400) return `${Math.floor(s / 3600)} h`;
  return `${Math.floor(s / 86400)} d`;
}

/** Classifica a saúde de um alvo pela latência. */
function health(rtt) {
  if (rtt === null || rtt === undefined) return { label: "Sem resposta", color: SEV.critical, icon: WifiOff };
  if (rtt < 30) return { label: "Ótima", color: C.ok, icon: Wifi };
  if (rtt < 80) return { label: "Boa", color: C.ok, icon: Wifi };
  if (rtt < 150) return { label: "Atenção", color: SEV.medium, icon: Activity };
  return { label: "Ruim", color: SEV.high, icon: Activity };
}

export default function Dashboard({ devices, changes, findings, scan, go, onScan }) {
  const tel = useTelemetry();

  // Três estados, não dois.
  //
  // 1. Varrendo e ainda sem resultado → estado de varredura ativa (não a tela
  //    de "escaneie", que era o bug: pedia para escanear DURANTE o scan).
  // 2. Sem dispositivos e sem varredura → convite para escanear.
  // 3. Com dispositivos → dashboard, que preenche ao vivo mesmo durante o scan.
  if (devices.length === 0 && scan?.running) {
    return <ScanningState phase={scan.phase} percent={scan.percent} found={0} />;
  }

  if (devices.length === 0) {
    return (
      <div className="rounded-lg" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
        <div className="flex flex-col items-center justify-center gap-3 py-20">
          <Gauge size={30} style={{ color: C.faint }} />
          <p className="text-sm" style={{ ...sans, color: C.dim }}>Nenhuma varredura ainda</p>
          <p className="text-xs text-center" style={{ ...sans, color: C.faint, maxWidth: 400 }}>
            Rode a primeira varredura para popular o inventário. A telemetria de rede começa
            automaticamente e o painel passa a mostrar latência e saúde em tempo real.
          </p>
          <button onClick={() => onScan()} className="rounded-md px-3.5 h-9 text-sm font-medium mt-1"
            style={{ ...sans, background: C.cyan, color: "#06090F" }}>Escanear rede</button>
        </div>
      </div>
    );
  }

  const online = devices.filter((d) => d.missCount === 0).length;
  const offline = devices.length - online;
  const crit = findings.filter((f) => f.severity === "critical");
  const unseen = changes.filter((c) => !c.acknowledged);

  // Distribuição de severidade para o donut.
  const sevData = BY_RANK.map((k) => ({
    name: k, value: findings.filter((f) => f.severity === k).length, color: SEV[k],
  })).filter((d) => d.value > 0);

  // Alvos de telemetria ordenados: gateway, dns, internet.
  const order = { gateway: 0, dns_internal: 1, dns_external: 2, internet: 3, custom: 4 };
  const targets = Object.entries(tel.latest)
    .map(([id, v]) => ({ id: Number(id), ...v, loss: tel.loss[id] || 0 }))
    .sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9));

  // Detecção de falhas: condições que merecem atenção agora.
  const faults = detectFaults({ tel, targets, devices, findings });

  return (
    <div className="flex flex-col gap-4">
      {/* Faixa de saúde da rede ao vivo */}
      <div className="grid grid-cols-4 gap-4">
        {targets.slice(0, 3).map((t) => {
          const h = health(t.rtt);
          return (
            <div key={t.id} className="rounded-lg p-4" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
              <div className="flex items-center justify-between">
                <p className="text-xs" style={{ ...sans, color: C.faint }}>{t.label}</p>
                <h.icon size={14} style={{ color: h.color }} />
              </div>
              <p className="mt-2 flex items-baseline gap-1">
                <span style={{ ...mono, color: h.color, fontSize: 26, fontWeight: 500, lineHeight: 1 }}>
                  {t.rtt === null ? "—" : t.rtt.toFixed(0)}
                </span>
                <span style={{ ...mono, color: C.dim, fontSize: 12 }}>ms</span>
              </p>
              <p className="text-xs mt-1.5" style={{ ...sans, color: C.faint }}>
                {h.label}{t.loss > 1 ? ` · ${t.loss.toFixed(0)}% perda` : ""}
              </p>
            </div>
          );
        })}

        {/* Inventário e alertas: número grande de dispositivos ativos, e os
            contadores que estavam no dashboard antigo logo abaixo. */}
        <div className="rounded-lg p-4" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
          <div className="flex items-center justify-between">
            <p className="text-xs" style={{ ...sans, color: C.faint }}>Dispositivos ativos</p>
            <Server size={14} style={{ color: C.cyan }} />
          </div>
          <p className="mt-2 flex items-baseline gap-1">
            <span style={{ ...mono, color: C.cyan, fontSize: 26, fontWeight: 500, lineHeight: 1 }}>{online}</span>
            <span style={{ ...mono, color: C.dim, fontSize: 12 }}>/ {devices.length}</span>
          </p>
          <div className="flex items-center gap-3 mt-2 flex-wrap">
            {offline > 0 && (
              <span className="text-xs inline-flex items-center gap-1" style={{ ...sans, color: SEV.info }}>
                <WifiOff size={11} /> {offline} ausente{offline > 1 ? "s" : ""}
              </span>
            )}
            {crit.length > 0 && (
              <span className="text-xs inline-flex items-center gap-1" style={{ ...sans, color: SEV.critical }}>
                <ShieldAlert size={11} /> {crit.length} crítico{crit.length > 1 ? "s" : ""}
              </span>
            )}
            {findings.length > 0 && (
              <span className="text-xs inline-flex items-center gap-1" style={{ ...sans, color: SEV.high }}>
                <AlertTriangle size={11} /> {findings.length} achado{findings.length > 1 ? "s" : ""}
              </span>
            )}
            {unseen.length > 0 && (
              <span className="text-xs inline-flex items-center gap-1" style={{ ...sans, color: C.purple }}>
                <GitCompareArrows size={11} /> {unseen.length} mudança{unseen.length > 1 ? "s" : ""}
              </span>
            )}
            {offline === 0 && crit.length === 0 && findings.length === 0 && unseen.length === 0 && (
              <span className="text-xs" style={{ ...sans, color: C.ok }}>tudo em ordem</span>
            )}
          </div>
        </div>
      </div>

      {/* Gráfico de latência ao vivo */}
      <section className="rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
        <header className="flex items-center justify-between px-4 h-11" style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
          <div className="flex items-center gap-2">
            <Activity size={14} style={{ color: C.cyan }} />
            <h2 className="text-sm font-medium" style={{ ...sans, color: C.text }}>Latência da rede ao vivo</h2>
          </div>
          <span className="flex items-center gap-1.5 text-xs" style={{ ...sans, color: tel.connected ? C.ok : C.faint }}>
            <span className="rounded-full" style={{ width: 6, height: 6, background: tel.connected ? C.ok : C.faint,
              boxShadow: tel.connected ? `0 0 6px ${C.ok}` : "none" }} />
            {tel.connected ? "ao vivo" : "conectando…"}
          </span>
        </header>
        <div className="p-3">
          {tel.series.length > 0
            ? <LatencyChart series={tel.series} height={240} />
            : <div className="flex items-center justify-center" style={{ height: 240 }}>
                <p className="text-sm" style={{ ...sans, color: C.faint }}>Coletando as primeiras medições…</p>
              </div>}
        </div>
      </section>

      <div className="grid grid-cols-3 gap-4">
        {/* Detecção de falhas */}
        <section className="col-span-2 rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
          <header className="flex items-center gap-2 px-4 h-11" style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
            <AlertTriangle size={14} style={{ color: faults.length ? SEV.high : C.ok }} />
            <h2 className="text-sm font-medium" style={{ ...sans, color: C.text }}>Detecção de falhas</h2>
          </header>
          {faults.length === 0 ? (
            <div className="flex items-center gap-2.5 py-8 justify-center">
              <ShieldCheck size={18} style={{ color: C.ok }} />
              <span className="text-sm" style={{ ...sans, color: C.dim }}>Nenhuma falha detectada. A rede está estável.</span>
            </div>
          ) : (
            faults.map((f, i) => (
              <div key={i} className="flex items-center gap-3 px-4 h-14 relative"
                style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
                <span className="absolute left-0 top-0 bottom-0" style={{ width: 3, background: f.color }} />
                <f.icon size={16} style={{ color: f.color }} className="shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm" style={{ ...sans, color: C.text }}>{f.title}</p>
                  <p className="text-xs" style={{ ...sans, color: C.faint }}>{f.detail}</p>
                </div>
                {f.action && (
                  <button onClick={() => go(f.action)} className="text-xs shrink-0" style={{ ...sans, color: C.cyan }}>
                    ver
                  </button>
                )}
              </div>
            ))
          )}
        </section>

        {/* Achados por severidade — donut */}
        <section className="rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
          <header className="flex items-center justify-between px-4 h-11" style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
            <h2 className="text-sm font-medium" style={{ ...sans, color: C.text }}>Achados</h2>
            <button onClick={() => go("findings")} className="text-xs" style={{ ...sans, color: C.cyan }}>ver todos</button>
          </header>
          <div className="p-4 flex items-center gap-4">
            {sevData.length > 0 ? (
              <>
                <div style={{ width: 100, height: 100 }}>
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={sevData} dataKey="value" innerRadius={30} outerRadius={48}
                        paddingAngle={2} stroke="none">
                        {sevData.map((d, i) => <Cell key={i} fill={d.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-col gap-1.5 flex-1">
                  {sevData.map((d) => (
                    <div key={d.name} className="flex items-center gap-2">
                      <span className="rounded-full" style={{ width: 7, height: 7, background: d.color }} />
                      <span className="text-xs flex-1" style={{ ...sans, color: C.dim }}>
                        {{ critical: "Crítica", high: "Alta", medium: "Média", low: "Baixa", info: "Info" }[d.name]}
                      </span>
                      <span className="text-sm" style={{ ...mono, color: C.text }}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex items-center gap-2 py-6 mx-auto">
                <ShieldCheck size={16} style={{ color: C.ok }} />
                <span className="text-sm" style={{ ...sans, color: C.dim }}>Sem achados abertos</span>
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Mudanças recentes */}
      <section className="rounded-lg overflow-hidden" style={{ background: C.panel, border: `1px solid ${C.line}` }}>
        <header className="flex items-center justify-between px-4 h-11" style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
          <div className="flex items-center gap-2">
            <GitCompareArrows size={14} style={{ color: C.purple }} />
            <h2 className="text-sm font-medium" style={{ ...sans, color: C.text }}>Mudanças recentes</h2>
          </div>
          <button onClick={() => go("changes")} className="text-xs" style={{ ...sans, color: C.cyan }}>ver tudo</button>
        </header>
        {unseen.length === 0 ? (
          <div className="px-4 py-8 text-center">
            <p className="text-sm" style={{ ...sans, color: C.faint }}>Nada mudou desde a última varredura.</p>
          </div>
        ) : (
          unseen.slice(0, 5).map((c) => (
            <button key={c.id} onClick={() => go("changes")}
              className="w-full flex items-center gap-3 px-4 h-14 text-left" style={{ borderBottom: `1px solid ${C.lineSoft}` }}>
              <span className="rounded-full shrink-0" style={{ width: 8, height: 8, background: SEV[c.severity] }} />
              <div className="flex-1 min-w-0">
                <span className="text-sm" style={{ ...sans, color: C.text }}>{CHANGE_LABEL[c.changeType] || c.changeType}</span>
                <span className="text-sm ml-2" style={{ ...mono, color: C.dim }}>{c.deviceIp || ""}</span>
                <p className="text-xs truncate" style={{ ...sans, color: C.faint }}>{c.after || ""}</p>
              </div>
              <span className="text-xs shrink-0" style={{ ...sans, color: C.faint }}>{ago(c.detectedAt)}</span>
            </button>
          ))
        )}
      </section>
    </div>
  );
}

/**
 * Detecção de falhas: lê o estado ao vivo e o inventário e destaca o que merece
 * atenção AGORA. É a diferença entre um painel que mostra números e um que
 * avisa antes de o usuário reclamar.
 */
function detectFaults({ tel, targets, devices, findings }) {
  const out = [];

  for (const t of targets) {
    if (t.rtt === null) {
      out.push({
        icon: WifiOff, color: SEV.critical,
        title: `${t.label} sem resposta`,
        detail: t.kind === "gateway"
          ? "O gateway não respondeu. Pode ser queda da rede local."
          : "Destino inalcançável na última medição.",
      });
    } else if (t.loss > 5) {
      out.push({
        icon: TrendingDown, color: SEV.high,
        title: `Perda de pacote em ${t.label}`,
        detail: `${t.loss.toFixed(0)}% dos pacotes se perderam. Voz e vídeo já sofrem acima de 1%.`,
      });
    } else if (t.rtt > 150 && t.kind === "gateway") {
      out.push({
        icon: Activity, color: SEV.medium,
        title: "Latência interna alta",
        detail: `${t.rtt.toFixed(0)}ms até o gateway indica saturação ou cabo com problema.`,
      });
    }
  }

  // Jitter: variação grande na janela, calculada das séries.
  for (const s of tel.series) {
    const vals = s.points.map((p) => p[1]).filter((v) => v !== null);
    if (vals.length < 5) continue;
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
    let jitterSum = 0;
    for (let i = 1; i < vals.length; i++) jitterSum += Math.abs(vals[i] - vals[i - 1]);
    const jitter = jitterSum / (vals.length - 1);
    if (jitter > 30) {
      out.push({
        icon: Activity, color: SEV.medium,
        title: `Jitter alto em ${s.label}`,
        detail: `Variação de ${jitter.toFixed(0)}ms. É o que trava chamada de voz e vídeo.`,
      });
    }
  }

  // Dispositivos que sumiram.
  const gone = devices.filter((d) => d.missCount > 0).length;
  if (gone > 0) {
    out.push({
      icon: WifiOff, color: SEV.info,
      title: `${gone} dispositivo${gone > 1 ? "s" : ""} ausente${gone > 1 ? "s" : ""}`,
      detail: "Não apareceram na última varredura.",
      action: "devices",
    });
  }

  // Achados críticos abertos.
  const crit = findings.filter((f) => f.severity === "critical").length;
  if (crit > 0) {
    out.push({
      icon: ShieldAlert, color: SEV.critical,
      title: `${crit} achado${crit > 1 ? "s" : ""} crítico${crit > 1 ? "s" : ""}`,
      detail: "Exigem ação imediata.",
      action: "findings",
    });
  }

  return out;
}