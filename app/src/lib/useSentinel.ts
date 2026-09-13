/**
 * Estado do aplicativo, ligado ao núcleo.
 *
 * Este hook substitui a constante DEVICES do protótipo. A troca no componente
 * é pequena: onde havia `useState(DEVICES)` e a simulação com setInterval,
 * passa a haver `useSentinel()`.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  api, events,
  type Capabilities, type ChangeRow, type DeviceDetail, type DeviceRow,
  type FindingInfo, type PortProfile, type RuleInfo, type ScanProgress,
} from "./api";

/** Rótulo de fase para a barra de progresso. */
export const PHASE_LABEL: Record<ScanProgress["phase"], string> = {
  discovery: "Procurando dispositivos",
  resolution: "Identificando",
  ports: "Verificando serviços",
  rules: "Avaliando riscos",
  diffing: "Comparando com a última varredura",
};

interface ScanState {
  running: boolean;
  phase: ScanProgress["phase"] | null;
  percent: number;
  lastResult: { found: number; new: number; gone: number } | null;
  error: string | null;
}

export function useSentinel(initialInterface = "") {
  const [iface, setIface] = useState(initialInterface);
  const [cidr, setCidr] = useState("");
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [devices, setDevices] = useState<DeviceRow[]>([]);
  const [changes, setChanges] = useState<ChangeRow[]>([]);
  const [findings, setFindings] = useState<FindingInfo[]>([]);
  /** Indexado por id para lookup direto na tela de Achados. */
  const [rules, setRules] = useState<Record<string, RuleInfo>>({});
  const [loading, setLoading] = useState(true);
  const [scan, setScan] = useState<ScanState>({
    running: false, phase: null, percent: 0, lastResult: null, error: null,
  });

  // Durante a varredura os dispositivos chegam um a um. Acumular em ref e
  // repassar para o estado evita re-render a cada evento: numa /24 são até
  // 254 eventos em poucos segundos, e atualizar o estado em todos trava a
  // interface justamente quando ela deveria parecer fluida.
  const buffer = useRef<Map<string, DeviceRow>>(new Map());
  const flushTimer = useRef<number | null>(null);

  const flush = useCallback(() => {
    if (flushTimer.current !== null) return;
    flushTimer.current = window.setTimeout(() => {
      flushTimer.current = null;
      setDevices(Array.from(buffer.current.values()).sort(byRisk));
    }, 120);
  }, []);

  // ---- carga inicial ------------------------------------------------------

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const ifaces = await api.listInterfaces();
        // Primeira interface não-loopback com rede válida. O loopback vem
        // por último na lista da core justamente para não ser escolhido.
        const pick = ifaces.find((i) => !i.isLoopback && i.network) ?? ifaces[0];
        if (!alive) return;

        if (pick) {
          setIface(pick.name);
          if (pick.network) setCidr(pick.network);
          setCaps(await api.getCapabilities(pick.name));
        }

        const [d, c, f, cat] = await Promise.all([
          api.devicesList(),
          api.changesList(),
          api.findingsList(),
          api.rulesCatalog(),
        ]);
        if (!alive) return;

        buffer.current = new Map(d.map((x) => [x.id, x]));
        setDevices(d.sort(byRisk));
        setChanges(c);
        setFindings(f);
        setRules(Object.fromEntries(cat.map((r) => [r.id, r])));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  // ---- eventos da varredura ----------------------------------------------

  useEffect(() => {
    const unsubs: Array<() => void> = [];

    events.onScanProgress((p) => {
      setScan((s) => ({
        ...s,
        running: true,
        phase: p.phase,
        percent: p.total ? Math.round((p.done / p.total) * 100) : 0,
      }));
    }).then((u) => unsubs.push(u));

    events.onScanDevice((e) => {
      buffer.current.set(e.device.id, e.device);
      flush();
    }).then((u) => unsubs.push(u));

    events.onScanFinished(async (summary) => {
      setScan({
        running: false, phase: null, percent: 100,
        lastResult: { found: summary.found, new: summary.new, gone: summary.gone },
        error: null,
      });
      // Recarrega do banco: durante a varredura os eventos trazem o
      // dispositivo, mas contagem de portas, achados e ausências só ficam
      // corretas depois que o diff comitou.
      const [devs, chs, finds] = await Promise.all([
        api.devicesList(),
        api.changesList(),
        api.findingsList(),
      ]);
      buffer.current = new Map(devs.map((x) => [x.id, x]));
      setDevices(devs.sort(byRisk));
      setChanges(chs);
      setFindings(finds);
    }).then((u) => unsubs.push(u));

    events.onScanFailed((error) => {
      setScan((s) => ({ ...s, running: false, error }));
    }).then((u) => unsubs.push(u));

    return () => unsubs.forEach((u) => u());
  }, [flush]);

  // ---- ações --------------------------------------------------------------

  const startScan = useCallback(async (profile: PortProfile = "common") => {
    if (!iface || !cidr) return;
    setScan({ running: true, phase: "discovery", percent: 0, lastResult: null, error: null });
    buffer.current.clear();
    setDevices([]);
    try {
      await api.scanStart(iface, cidr, profile);
    } catch (e) {
      setScan((s) => ({ ...s, running: false, error: String(e) }));
    }
  }, [iface, cidr]);

  const cancelScan = useCallback(async () => {
    await api.scanCancel();
    setScan((s) => ({ ...s, running: false }));
  }, []);

  const ackChange = useCallback(async (id: number) => {
    await api.changeAck(id);
    setChanges((cs) => cs.map((c) => (c.id === id ? { ...c, acknowledged: true } : c)));
  }, []);

  const renameDevice = useCallback(async (id: string, label: string) => {
    await api.deviceUpdate(id, { label });
    setDevices((ds) => ds.map((d) => (d.id === id ? { ...d, label } : d)));
  }, []);

  /** Carregado sob demanda ao abrir o detalhe: portas e achados daquele host. */
  const loadDetail = useCallback(
    (id: string): Promise<DeviceDetail> => api.deviceDetail(id),
    [],
  );

  const acceptFinding = useCallback(async (id: number, reason: string) => {
    await api.findingAccept(id, reason);
    setFindings((fs) => fs.filter((f) => f.id !== id));
  }, []);

  return {
    iface, setIface, cidr, setCidr,
    caps, devices, changes, findings, rules, loading, scan,
    startScan, cancelScan, ackChange, renameDevice, loadDetail, acceptFinding,
    unseenChanges: changes.filter((c) => !c.acknowledged).length,
  };
}

/** Pior risco primeiro; dentro do mesmo risco, por IP numérico. */
function byRisk(a: DeviceRow, b: DeviceRow) {
  const ra = a.worstSeverityRank ?? 99;
  const rb = b.worstSeverityRank ?? 99;
  if (ra !== rb) return ra - rb;
  return ipValue(a.ip) - ipValue(b.ip);
}

function ipValue(ip: string | null): number {
  if (!ip) return 0;
  return ip.split(".").reduce((acc, part) => acc * 256 + Number(part), 0);
}