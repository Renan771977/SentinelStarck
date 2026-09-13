/**
 * Ponte tipada entre React e o núcleo em Rust.
 *
 * Nenhum componente chama `invoke` direto. Tudo passa por aqui, por dois
 * motivos: os tipos ficam num lugar só, e trocar o transporte depois (de IPC
 * do Tauri para HTTP, no dia em que o núcleo virar serviço) muda este arquivo
 * e mais nada.
 *
 * Os tipos abaixo devem ser GERADOS a partir do Rust com `ts-rs` ou `specta`,
 * não escritos à mão. Estão explícitos aqui só para deixar o contrato visível.
 * Sem geração automática, todo campo novo no Rust vira bug silencioso aqui.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/**
 * "none" salta a fase de portas: varredura de presença em segundos, sem tocar
 * em serviço nenhum. Nenhum achado baseado em porta é avaliado nem resolvido.
 */
export type PortProfile = "none" | "common" | "extended";
export type Confidence = "high" | "medium" | "low";

export type DeviceKind =
  | "router" | "switch" | "firewall" | "server" | "workstation"
  | "printer" | "camera" | "nas" | "ap" | "phone" | "iot" | "unknown";

export interface Capabilities {
  arpActive: boolean;
  passiveListen: boolean;
  tcpConnect: boolean;
  icmp: boolean;
  /** Texto pronto para a tela quando algo está indisponível. */
  reason: string | null;
}

export interface InterfaceInfo {
  name: string;
  /** Endereço do próprio host: "192.168.1.37/24". */
  address: string | null;
  /** A rede a varrer, já calculada no Rust: "192.168.1.0/24". */
  network: string | null;
  isLoopback: boolean;
  /**
   * Se a varredura ARP funciona nesta interface. Testado de verdade, abrindo
   * o canal de enlace. Adaptador virtual costuma vir `false`.
   */
  arpCapable: boolean;
}

export interface DeviceRow {
  id: string;
  label: string | null;
  ip: string | null;
  mac: string | null;
  kind: DeviceKind;
  vendor: string | null;
  osGuess: string | null;
  identityConfidence: Confidence;
  hostname: string | null;
  /** Primeira observação deste dispositivo nesta rede. Base da linha do tempo. */
  firstSeen: number;
  lastSeen: number;
  missCount: number;
  /** Quantos IPs diferentes já teve. Alto indica DHCP instável ou evasão. */
  ipHistoryCount: number;
  openPorts: number;
  findingCount: number;
  /** 0 = crítica … 4 = info. null quando não há achado aberto. */
  worstSeverityRank: number | null;
}

export interface RuleInfo {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: string;
  /** Por que isso importa. Escrito no rules.toml, não aqui. */
  why: string;
  /** Como corrigir. */
  fix: string;
  enabled: boolean;
  requiresConsent: boolean;
}

export interface AddressInfo {
  kind: "mac" | "ip";
  value: string;
  isCurrent: boolean;
}

export interface TlsInfo {
  protocol: string;
  subject: string | null;
  issuer: string | null;
  san: string[];
  notBefore: number | null;
  notAfter: number | null;
  keyType: string | null;
  keyBits: number | null;
  selfSigned: boolean;
  signatureAlgorithm: string | null;
}

export type HintKind = "shell" | "browser" | "external" | "info";

export interface ConnectHint {
  label: string;
  /** Comando pronto, com IP e porta preenchidos. */
  command: string;
  kind: HintKind;
  /** Presente quando o protocolo é inseguro. */
  warning: string | null;
}

export interface ServiceInfo {
  protocol: string;
  port: number;
  serviceName: string | null;
  banner: string | null;
  /** JSON serializado de TlsInfo, ou null quando a porta não fala TLS. */
  tlsInfo: string | null;
  /** Comandos de conexão sugeridos para esta porta. */
  connectHints: ConnectHint[];
}

export interface FindingInfo {
  id: number;
  deviceId: string;
  deviceIp: string | null;
  ruleId: string;
  /** "tcp/80" quando a mesma regra vale para mais de uma porta. */
  scope: string | null;
  severity: Severity;
  confidence: string;
  evidence: string | null;
  firstSeen: number;
  accepted: boolean;
}

export interface DeviceDetail {
  id: string;
  label: string | null;
  kind: DeviceKind;
  vendor: string | null;
  osGuess: string | null;
  hostname: string | null;
  identityConfidence: Confidence;
  firstSeen: number;
  lastSeen: number;
  notes: string | null;
  addresses: AddressInfo[];
  services: ServiceInfo[];
  findings: FindingInfo[];
}

export interface ChangeRow {
  id: number;
  deviceId: string;
  deviceIp: string | null;
  deviceLabel: string | null;
  changeType:
    | "device_new" | "device_gone" | "device_returned"
    | "port_opened" | "port_closed"
    | "ip_changed" | "mac_changed" | "hostname_changed"
    | "vendor_conflict" | "os_changed";
  severity: Severity;
  before: string | null;
  after: string | null;
  detectedAt: number;
  acknowledged: boolean;
}

// ---------------------------------------------------------------------------
// Eventos
// ---------------------------------------------------------------------------

export interface ScanProgress {
  scanId: string;
  phase: "discovery" | "resolution" | "ports" | "rules" | "diffing";
  done: number;
  total: number;
}

export interface ScanDeviceEvent {
  scanId: string;
  /** Linha completa, igual à da lista: a ponte recarrega do banco. */
  device: DeviceRow;
  isNew: boolean;
}

export interface ScanFinished {
  scanId: string;
  found: number;
  new: number;
  gone: number;
}

// ---------------------------------------------------------------------------
// Comandos
// ---------------------------------------------------------------------------

export const api = {
  getCapabilities: (iface: string) =>
    invoke<Capabilities>("get_capabilities", { interface: iface }),

  listInterfaces: () => invoke<InterfaceInfo[]>("list_interfaces"),

  /** Retorna assim que a varredura começa. Os resultados chegam por evento. */
  scanStart: (iface: string, targetCidr: string, portProfile: PortProfile = "common") =>
    invoke<void>("scan_start", { interface: iface, targetCidr, portProfile }),

  scanCancel: () => invoke<void>("scan_cancel"),
  scanIsRunning: () => invoke<boolean>("scan_is_running"),

  devicesList: () => invoke<DeviceRow[]>("devices_list"),

  changesList: (includeAcknowledged = false) =>
    invoke<ChangeRow[]>("changes_list", { includeAcknowledged }),

  changeAck: (id: number) => invoke<void>("change_ack", { id }),

  deviceUpdate: (
    id: string,
    patch: { label?: string; kind?: DeviceKind; notes?: string },
  ) => invoke<void>("device_update", { id, ...patch }),

  /**
   * Só chame depois do diálogo de consentimento. Sem registro aqui, o motor
   * nem avalia as regras CRED-*, que tentam autenticar e podem bloquear conta.
   */
  credentialConsentGrant: (deviceId: string, note?: string, validDays?: number) =>
    invoke<void>("credential_consent_grant", { deviceId, note, validDays }),

  credentialConsentRevoke: (deviceId: string) =>
    invoke<void>("credential_consent_revoke", { deviceId }),

  /** Carregado uma vez na inicialização. O texto vem do rules.toml. */
  rulesCatalog: () => invoke<RuleInfo[]>("rules_catalog"),

  deviceDetail: (id: string) => invoke<DeviceDetail>("device_detail", { id }),

  findingsList: () => invoke<FindingInfo[]>("findings_list"),

  findingAccept: (id: number, reason: string, validDays?: number) =>
    invoke<void>("finding_accept", { id, reason, validDays }),

  /** Falso quando o binário foi compilado sem a feature `terminal`. */
  terminalAvailable: () => invoke<boolean>("terminal_available"),

  /**
   * Exporta a evidência selada. Abre diálogo de pasta, grava manifesto .json e
   * relatório .html, retorna o hash e os caminhos.
   */
  exportEvidence: (scope: string) =>
    invoke<{
      hash: string;
      manifestPath: string;
      reportPath: string;
      deviceCount: number;
      findingCount: number;
    }>("export_evidence", { scope }),

  exclusionsList: () => invoke<string[]>("exclusions_list"),
  exclusionAdd: (target: string, reason?: string) =>
    invoke<void>("exclusion_add", { target, reason }),
};

// ---------------------------------------------------------------------------
// Assinatura de eventos
// ---------------------------------------------------------------------------

export const events = {
  onScanProgress: (cb: (p: ScanProgress) => void): Promise<UnlistenFn> =>
    listen<ScanProgress>("scan:progress", (e) => cb(e.payload)),

  onScanDevice: (cb: (d: ScanDeviceEvent) => void): Promise<UnlistenFn> =>
    listen<ScanDeviceEvent>("scan:device", (e) => cb(e.payload)),

  onScanFinished: (cb: (f: ScanFinished) => void): Promise<UnlistenFn> =>
    listen<ScanFinished>("scan:finished", (e) => cb(e.payload)),

  onScanFailed: (cb: (err: string) => void): Promise<UnlistenFn> =>
    listen<{ error: string }>("scan:failed", (e) => cb(e.payload.error)),
};