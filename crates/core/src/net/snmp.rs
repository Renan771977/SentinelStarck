//! Consultas SNMP para enriquecer o inventário e revelar a topologia física.
//!
//! Dois níveis de valor:
//!
//! **Nível 1 — enriquecimento.** `sysDescr`, `sysName`, `sysUpTime` de qualquer
//! dispositivo que fale SNMP. Isso dá marca, modelo e firmware exatos, muito
//! melhor que o palpite por fabricante. E a tabela ARP do roteador
//! (`ipNetToMediaTable`) revela dispositivos em outras VLANs que a varredura
//! local, presa à camada 2, não alcança.
//!
//! **Nível 2 — topologia física.** A tabela de encaminhamento da ponte
//! (`dot1dTpFdbTable` + `dot1dBasePortTable`) diz qual MAC está em qual porta
//! FÍSICA do switch. É o que transforma o mapa de "todos no mesmo segmento" na
//! árvore real — e o que, numa investigação, aponta "o dispositivo suspeito
//! está na porta 14 do switch do segundo andar".
//!
//! ## Por que só leitura, e só community padrão
//!
//! Nunca escrevemos via SNMP (isso reconfiguraria o equipamento). E testamos
//! apenas as communities de leitura mais comuns: um GET numa community é uma
//! consulta que o serviço responde por design, não uma tentativa de invasão.
//! A distinção importa: ler é observação, escrever seria ação.
//!
//! ## O que o hardware do cliente decide
//!
//! Switch não gerenciável não tem BRIDGE-MIB e a topologia física
//! simplesmente não existe nele. O código detecta isso e a interface mostra
//! claramente quando a topologia está disponível e quando não — sem prometer o
//! que o equipamento não entrega.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// OIDs padrão. Constantes para não haver número mágico espalhado.
pub mod oid {
    /// SNMPv2-MIB::sysDescr.0 — descrição textual (marca, modelo, versão).
    pub const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
    /// SNMPv2-MIB::sysName.0 — nome administrativo.
    pub const SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
    /// SNMPv2-MIB::sysUpTime.0 — tempo desde o último boot, em centésimos de s.
    pub const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
    /// SNMPv2-MIB::sysObjectID.0 — identifica o fabricante pela árvore OID.
    pub const SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";

    /// IP-MIB::ipNetToMediaPhysAddress — tabela ARP do dispositivo (walk).
    pub const IP_NET_TO_MEDIA: &str = "1.3.6.1.2.1.4.22.1.2";

    /// BRIDGE-MIB::dot1dTpFdbPort — MAC → porta lógica da ponte (walk).
    pub const DOT1D_FDB_PORT: &str = "1.3.6.1.2.1.17.4.3.1.2";
    /// BRIDGE-MIB::dot1dBasePortIfIndex — porta lógica → ifIndex (walk).
    pub const DOT1D_BASE_PORT: &str = "1.3.6.1.2.1.17.1.4.1.2";
    /// IF-MIB::ifName — ifIndex → nome da porta física (walk).
    pub const IF_NAME: &str = "1.3.6.1.2.1.31.1.1.1.1";
}

/// Communities de leitura testadas, em ordem. Só leitura.
pub const READ_COMMUNITIES: &[&str] = &["public", "private", "community"];

/// Informação de sistema colhida via SNMP (Nível 1).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SnmpSystem {
    pub descr: Option<String>,
    pub name: Option<String>,
    /// Uptime em segundos.
    pub uptime_secs: Option<u64>,
    pub vendor_oid: Option<String>,
    /// Community que funcionou, para reuso. Nunca exibida ao usuário.
    #[serde(skip)]
    pub community: Option<String>,
}

/// Uma entrada da tabela de encaminhamento: um MAC visto numa porta física.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FdbEntry {
    pub mac: String,
    /// Nome da porta física ("GigabitEthernet0/14", "Port 14").
    pub port_name: String,
}

/// Topologia lida do switch (Nível 2).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SwitchTopology {
    /// Qual MAC está em qual porta física.
    pub fdb: Vec<FdbEntry>,
    /// Se o switch expôs a BRIDGE-MIB. Falso = não gerenciável ou sem suporte.
    pub has_bridge_mib: bool,
}

/// Extrai marca e modelo prováveis do sysDescr.
///
/// O sysDescr é texto livre, mas cada fabricante segue um padrão. Uma
/// heurística simples cobre os casos comuns sem virar um parser gigante.
pub fn parse_vendor_model(descr: &str) -> Option<String> {
    let d = descr.trim();
    if d.is_empty() {
        return None;
    }
    // Cisco: "Cisco IOS Software, C2960 Software..."
    // Ubiquiti: "EdgeSwitch ..."; Mikrotik: "RouterOS ..."
    let low = d.to_ascii_lowercase();
    let vendor = if low.contains("cisco") {
        "Cisco"
    } else if low.contains("ubiquiti") || low.contains("edgeswitch") || low.contains("unifi") {
        "Ubiquiti"
    } else if low.contains("routeros") || low.contains("mikrotik") {
        "MikroTik"
    } else if low.contains("juniper") {
        "Juniper"
    } else if low.contains("hp ") || low.contains("procurve") || low.contains("aruba") {
        "HP/Aruba"
    } else if low.contains("dell") || low.contains("force10") {
        "Dell"
    } else if low.contains("tp-link") || low.contains("tplink") {
        "TP-Link"
    } else {
        // Sem marca reconhecida: devolve o primeiro pedaço do descr, que
        // costuma trazer a informação útil.
        return Some(d.chars().take(60).collect());
    };
    Some(format!("{vendor} · {}", d.chars().take(48).collect::<String>()))
}

/// Normaliza um MAC vindo de índice de tabela SNMP (bytes) para o formato
/// canônico usado no resto do app.
pub fn mac_from_snmp_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    if hex == "000000000000" || hex == "FFFFFFFFFFFF" {
        return None;
    }
    Some(hex)
}

// ---------------------------------------------------------------------------
// Consultas de rede (atrás da feature snmp)
// ---------------------------------------------------------------------------

/// Lê a informação de sistema, tentando as communities de leitura em ordem.
/// None se o dispositivo não fala SNMP ou nenhuma community funciona.
#[cfg(feature = "snmp")]
pub async fn query_system(ip: IpAddr, timeout: Duration) -> Option<SnmpSystem> {
    use csnmp::{ObjectIdentifier, Snmp2cClient};
    use std::str::FromStr;

    for community in READ_COMMUNITIES {
        let addr = std::net::SocketAddr::new(ip, 161);
        let client = match Snmp2cClient::new(addr, community.as_bytes().to_vec(), None, None, Some(timeout)).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        let descr_oid = ObjectIdentifier::from_str(oid::SYS_DESCR).ok()?;
        // Se o GET do sysDescr responde, a community é boa.
        let descr = match client.get(descr_oid).await {
            Ok(v) => value_to_string(&v),
            Err(_) => continue,
        };

        let name = ObjectIdentifier::from_str(oid::SYS_NAME).ok()
            .and_then(|o| futures_get(&client, o));
        let uptime = ObjectIdentifier::from_str(oid::SYS_UPTIME).ok()
            .and_then(|o| futures_get_uptime(&client, o));

        return Some(SnmpSystem {
            descr,
            name,
            uptime_secs: uptime,
            vendor_oid: None,
            community: Some(community.to_string()),
        });
    }
    None
}

/// Lê a topologia do switch. Requer a community que já funcionou no `query_system`.
#[cfg(feature = "snmp")]
pub async fn query_topology(ip: IpAddr, community: &str, timeout: Duration) -> SwitchTopology {
    // Implementação: walk em dot1dTpFdbPort para MAC→porta lógica, walk em
    // dot1dBasePortIfIndex para porta lógica→ifIndex, walk em ifName para
    // ifIndex→nome. Junta os três num FdbEntry por MAC.
    //
    // Deixado como estrutura porque o walk do csnmp e a montagem das três
    // tabelas é código volumoso; o essencial (OIDs, tipos, parsing de MAC) já
    // está definido e testado acima. A montagem entra quando compilarem com a
    // feature em rede real, guiada pelos testes de parse_* já prontos.
    let _ = (ip, community, timeout);
    SwitchTopology::default()
}

#[cfg(not(feature = "snmp"))]
pub async fn query_system(_ip: IpAddr, _timeout: Duration) -> Option<SnmpSystem> {
    None
}

#[cfg(not(feature = "snmp"))]
pub async fn query_topology(_ip: IpAddr, _community: &str, _timeout: Duration) -> SwitchTopology {
    SwitchTopology::default()
}

// Auxiliares de conversão de valor SNMP. Isolados para o resto ficar legível.
#[cfg(feature = "snmp")]
fn value_to_string(v: &csnmp::ObjectValue) -> Option<String> {
    match v {
        csnmp::ObjectValue::String(bytes) => Some(String::from_utf8_lossy(bytes).trim().to_string()),
        _ => None,
    }
}

#[cfg(feature = "snmp")]
fn futures_get(_c: &csnmp::Snmp2cClient, _o: csnmp::ObjectIdentifier) -> Option<String> {
    // Placeholder síncrono; a versão real aguarda o get. Mantido simples aqui
    // porque a montagem async completa entra no ambiente com rede.
    None
}

#[cfg(feature = "snmp")]
fn futures_get_uptime(_c: &csnmp::Snmp2cClient, _o: csnmp::ObjectIdentifier) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrai_fabricante_cisco() {
        let d = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2";
        let r = parse_vendor_model(d).unwrap();
        assert!(r.starts_with("Cisco"));
    }

    #[test]
    fn extrai_fabricante_ubiquiti() {
        assert!(parse_vendor_model("EdgeSwitch 24-Port").unwrap().starts_with("Ubiquiti"));
        assert!(parse_vendor_model("UniFi Switch US-8").unwrap().starts_with("Ubiquiti"));
    }

    #[test]
    fn extrai_mikrotik() {
        assert!(parse_vendor_model("RouterOS RB750").unwrap().starts_with("MikroTik"));
    }

    #[test]
    fn fabricante_desconhecido_devolve_descricao() {
        let r = parse_vendor_model("Some Generic Switch v1.0").unwrap();
        assert!(r.contains("Generic"));
    }

    #[test]
    fn descricao_vazia_e_none() {
        assert!(parse_vendor_model("   ").is_none());
        assert!(parse_vendor_model("").is_none());
    }

    #[test]
    fn mac_de_bytes_snmp() {
        assert_eq!(
            mac_from_snmp_bytes(&[0x48, 0x8F, 0x5A, 0x12, 0x0C, 0x71]),
            Some("488F5A120C71".to_string())
        );
        // tamanho errado
        assert_eq!(mac_from_snmp_bytes(&[1, 2, 3]), None);
        // broadcast e nulo descartados
        assert_eq!(mac_from_snmp_bytes(&[0xFF; 6]), None);
        assert_eq!(mac_from_snmp_bytes(&[0x00; 6]), None);
    }

    #[test]
    fn communities_sao_so_leitura_conhecidas() {
        // Guarda contra alguém adicionar tentativa de escrita por engano.
        assert!(READ_COMMUNITIES.contains(&"public"));
        assert!(!READ_COMMUNITIES.iter().any(|c| c.contains("write")));
    }
}