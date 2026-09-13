//! Tipos compartilhados entre motor, banco e interface.
//!
//! REGRA: todo tipo que cruza a fronteira para o frontend leva
//! `#[serde(rename_all = "camelCase")]`. Sem isso o Rust manda `arp_active` e
//! o TypeScript lê `arpActive`, que vira `undefined` — e `undefined` é falso,
//! então o erro não estoura: ele aparece como funcionalidade que "não liga",
//! e custa horas para achar. A geração automática de tipos com `ts-rs` mataria
//! essa classe inteira de bug de uma vez.
//!
//! Tudo aqui deriva Serialize para poder cruzar a fronteira do Tauri sem
//! conversão manual. No app real, anote também com `#[derive(TS)]` da crate
//! `ts-rs` para gerar os tipos TypeScript automaticamente: sem isso, todo
//! campo novo vira bug silencioso no frontend.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// MAC
// ---------------------------------------------------------------------------

/// Endereço MAC normalizado: 12 caracteres hex maiúsculos, sem separador.
///
/// A normalização acontece aqui e em nenhum outro lugar. `ip neigh` devolve
/// minúsculo com dois-pontos, o Windows devolve maiúsculo com hífen, e o pnet
/// devolve struct. Se cada ponto de entrada normalizar do seu jeito, o matcher
/// deixa de casar e o inventário duplica.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mac(String);

impl Mac {
    pub fn parse(raw: &str) -> Option<Self> {
        let hex: String = raw
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if hex.len() != 12 || hex == "000000000000" || hex == "FFFFFFFFFFFF" {
            return None;
        }
        Some(Mac(hex))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Primeiros 6 dígitos: o OUI, usado para descobrir o fabricante.
    pub fn oui(&self) -> &str {
        &self.0[..6]
    }

    /// Bit "local administrado" ligado no primeiro octeto.
    ///
    /// Indica MAC randomizado (celular e notebook modernos trocam de MAC por
    /// rede) ou máquina virtual. Nesses casos o MAC **não serve como chave
    /// forte de identidade** e o matcher precisa cair para hostname.
    pub fn is_randomized(&self) -> bool {
        u8::from_str_radix(&self.0[..2], 16)
            .map(|b| b & 0x02 != 0)
            .unwrap_or(false)
    }

    /// Forma de exibição: AA:BB:CC:DD:EE:FF. Só para a interface.
    pub fn display(&self) -> String {
        self.0
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":")
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Router,
    Switch,
    Firewall,
    Server,
    Workstation,
    Printer,
    Camera,
    Nas,
    Ap,
    Phone,
    Iot,
    /// Padrão deliberado: na dúvida, o dispositivo recebe o tratamento mais
    /// conservador de varredura. Pode ser um CLP de linha de produção.
    #[default]
    Unknown,
}

impl DeviceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::Switch => "switch",
            Self::Firewall => "firewall",
            Self::Server => "server",
            Self::Workstation => "workstation",
            Self::Printer => "printer",
            Self::Camera => "camera",
            Self::Nas => "nas",
            Self::Ap => "ap",
            Self::Phone => "phone",
            Self::Iot => "iot",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// Como o dispositivo foi observado. Determina a confiança da identidade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// ARP ativo com socket raw. Entrega MAC confiável.
    Arp,
    /// Tabela de vizinhança do sistema operacional. Entrega MAC sem privilégio.
    Neighbor,
    /// Conexão TCP respondeu. Prova que o host existe, mas não dá MAC.
    Tcp,
    Icmp,
    Passive,
    Snmp,
    Mdns,
    Dhcp,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Neighbor => "neighbor",
            Self::Tcp => "tcp",
            Self::Icmp => "icmp",
            Self::Passive => "passive",
            Self::Snmp => "snmp",
            Self::Mdns => "mdns",
            Self::Dhcp => "dhcp",
        }
    }
}

// ---------------------------------------------------------------------------
// Observação e dispositivo
// ---------------------------------------------------------------------------

/// O que uma sonda viu, antes de qualquer decisão de identidade.
///
/// Persistir isto cru permite reprocessar a identidade quando a heurística
/// melhorar, sem perder histórico.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub ip: Option<IpAddr>,
    pub mac: Option<Mac>,
    pub hostname: Option<String>,
    pub ttl: Option<u8>,
    pub rtt_ms: Option<f64>,
    pub method: Method,
    pub observed_at: i64,
}

/// A entidade estável. O `id` nunca muda, mesmo que IP, MAC e nome mudem.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub label: Option<String>,
    pub label_pinned: bool,
    pub kind: DeviceKind,
    pub kind_source: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub os_guess: Option<String>,
    pub identity_confidence: Confidence,
    pub first_seen: i64,
    pub last_seen: i64,
    pub miss_count: i32,
    pub is_ignored: bool,
}

// ---------------------------------------------------------------------------
// Varredura
// ---------------------------------------------------------------------------

/// O que o motor consegue fazer com o privilégio disponível agora.
///
/// A interface consome isto para desabilitar botão com explicação, em vez de
/// deixar o usuário clicar e receber erro.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub arp_active: bool,
    pub passive_listen: bool,
    pub tcp_connect: bool,
    pub icmp: bool,
    /// Motivo legível quando algo está indisponível. Vai direto para a tela.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanConfig {
    pub interface: String,
    pub target_cidr: String,
    pub kind: String,
    /// 'none' salta a fase de portas inteira, o que também impede que
    /// qualquer achado baseado em porta seja resolvido nesta varredura.
    pub port_profile: PortProfile,
    /// Faixas e IPs que nunca devem receber pacote ativo.
    ///
    /// Aplicada na camada mais baixa do motor. Impressora antiga e equipamento
    /// industrial travam com varredura, e isso não é lenda.
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProfile {
    /// Só descoberta. Rápido, e nenhuma regra de porta é avaliada.
    None,
    /// As 147 portas do perfil comum.
    Common,
    /// Comum mais UDP.
    Extended,
}

impl PortProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Common => "common",
            Self::Extended => "extended",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    /// Quem está na rede.
    Discovery,
    /// Nome, fabricante, identidade.
    Resolution,
    /// Portas, banner e sondas ativas.
    Ports,
    /// Avaliação do catálogo de regras.
    Rules,
    /// Comparação com o estado anterior.
    Diffing,
}

/// Eventos emitidos durante a varredura.
///
/// O núcleo não conhece o Tauri: ele manda por um canal. Quem consome decide
/// se vira `emit()` para o frontend ou linha no terminal do CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[serde(rename_all_fields = "camelCase")]
pub enum ScanEvent {
    Progress {
        scan_id: String,
        phase: ScanPhase,
        done: usize,
        total: usize,
    },
    /// Um por descoberta. É isto que faz a lista encher na tela em vez de
    /// aparecer de uma vez no fim.
    Device {
        scan_id: String,
        device: Device,
        is_new: bool,
    },
    Finished {
        scan_id: String,
        found: usize,
        new: usize,
        gone: usize,
    },
    Failed {
        scan_id: String,
        error: String,
    },
}

// ---------------------------------------------------------------------------
// Mudanças
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    DeviceNew,
    DeviceGone,
    DeviceReturned,
    PortOpened,
    PortClosed,
    IpChanged,
    MacChanged,
    HostnameChanged,
    VendorConflict,
    OsChanged,
}

impl ChangeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceNew => "device_new",
            Self::DeviceGone => "device_gone",
            Self::DeviceReturned => "device_returned",
            Self::PortOpened => "port_opened",
            Self::PortClosed => "port_closed",
            Self::IpChanged => "ip_changed",
            Self::MacChanged => "mac_changed",
            Self::HostnameChanged => "hostname_changed",
            Self::VendorConflict => "vendor_conflict",
            Self::OsChanged => "os_changed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub device_id: String,
    pub change_type: ChangeType,
    pub severity: Severity,
    pub before: Option<String>,
    pub after: Option<String>,
    pub detected_at: i64,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normaliza_formatos_diferentes() {
        let a = Mac::parse("a4:83:e7:1b:2c:0d").unwrap();
        let b = Mac::parse("A4-83-E7-1B-2C-0D").unwrap();
        let c = Mac::parse("a483.e71b.2c0d").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a.as_str(), "A483E71B2C0D");
        assert_eq!(a.display(), "A4:83:E7:1B:2C:0D");
    }

    #[test]
    fn mac_rejeita_invalidos() {
        assert!(Mac::parse("00:00:00:00:00:00").is_none());
        assert!(Mac::parse("ff:ff:ff:ff:ff:ff").is_none());
        assert!(Mac::parse("incompleto").is_none());
    }

    #[test]
    fn detecta_mac_randomizado() {
        // 0x7A = 0111_1010, bit 1 ligado
        assert!(Mac::parse("7A:11:C3:9E:02:D4").unwrap().is_randomized());
        // 0xA4 = 1010_0100, bit 1 desligado
        assert!(!Mac::parse("A4:83:E7:1B:2C:0D").unwrap().is_randomized());
    }
}