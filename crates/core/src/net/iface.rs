//! Listagem de interfaces de rede.
//!
//! Deliberadamente SEM pnet. A tela precisa oferecer uma interface e uma faixa
//! para varrer mesmo quando o binário está em modo limitado, e o pnet exige
//! libpcap no Linux e o SDK do Npcap no Windows. Aqui é getifaddrs no Unix e
//! GetAdaptersAddresses no Windows, que sempre existem.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub name: String,
    /// Endereço do próprio host, em forma CIDR: "192.168.1.37/24".
    pub address: Option<String>,
    /// A REDE correspondente, que é o que se varre: "192.168.1.0/24".
    pub network: Option<String>,
    pub is_loopback: bool,
}

/// Interfaces IPv4 ativas, loopback por último.
pub fn list() -> Vec<InterfaceInfo> {
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };

    let mut out: Vec<InterfaceInfo> = addrs
        .into_iter()
        .filter_map(|i| {
            let v4 = match i.addr {
                if_addrs::IfAddr::V4(ref a) => a.clone(),
                _ => return None,
            };
            let prefix = mask_to_prefix(v4.netmask);
            Some(InterfaceInfo {
                name: i.name.clone(),
                address: Some(format!("{}/{}", v4.ip, prefix)),
                network: network_of(v4.ip, prefix),
                is_loopback: i.is_loopback(),
            })
        })
        .collect();

    // Loopback existe mas nunca é o que o usuário quer varrer.
    out.sort_by_key(|i| i.is_loopback);
    out
}

/// IPv4 atual de uma interface, pelo nome amigável.
///
/// É a ponte entre dois espaços de nomes incompatíveis. O `if-addrs` (e a
/// tela) usa "Ethernet", "enp3s0", "en0". O `pnet` no Windows usa o caminho do
/// dispositivo NPF, tipo `\Device\NPF_{A1B2-...}`, que ninguém consegue
/// adivinhar. O endereço IP é a única coisa que os dois reportam igual.
pub fn ipv4_of(name: &str) -> Option<Ipv4Addr> {
    if_addrs::get_if_addrs().ok()?.into_iter().find_map(|i| {
        if i.name != name {
            return None;
        }
        match i.addr {
            if_addrs::IfAddr::V4(a) => Some(a.ip),
            _ => None,
        }
    })
}

/// Índice do adaptador, pelo nome amigável.
///
/// O índice vem da mesma tabela do sistema que o pnet lê, então é a ponte
/// confiável entre os dois no Windows, onde o pnet não traz os IPs e o
/// casamento por endereço falha.
pub fn index_of(name: &str) -> Option<u32> {
    if_addrs::get_if_addrs().ok()?.into_iter().find_map(|i| {
        if i.name == name {
            i.index
        } else {
            None
        }
    })
}

/// Primeira interface não-loopback com IPv4. Usada quando o chamador não
/// informa nome nenhum.
pub fn default_ipv4() -> Option<(String, Ipv4Addr)> {
    list().into_iter().find(|i| !i.is_loopback).and_then(|i| {
        let ip = i.address?.split('/').next()?.parse().ok()?;
        Some((i.name, ip))
    })
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// "192.168.1.37" + 24 -> "192.168.1.0/24"
fn network_of(ip: Ipv4Addr, prefix: u8) -> Option<String> {
    if prefix == 0 || prefix > 32 {
        return None;
    }
    let bits = u32::from(ip);
    let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    Some(format!("{}/{}", Ipv4Addr::from(bits & mask), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converte_mascara_em_prefixo() {
        assert_eq!(mask_to_prefix("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(mask_to_prefix("255.255.0.0".parse().unwrap()), 16);
        assert_eq!(mask_to_prefix("255.255.255.248".parse().unwrap()), 29);
    }

    #[test]
    fn calcula_a_rede_do_endereco() {
        assert_eq!(
            network_of("192.168.1.37".parse().unwrap(), 24).unwrap(),
            "192.168.1.0/24"
        );
        assert_eq!(
            network_of("10.0.5.200".parse().unwrap(), 16).unwrap(),
            "10.0.0.0/16"
        );
        assert_eq!(
            network_of("172.16.8.9".parse().unwrap(), 12).unwrap(),
            "172.16.0.0/12"
        );
    }

    /// Sempre deve haver pelo menos o loopback, em qualquer sistema.
    #[test]
    fn lista_alguma_interface() {
        assert!(!list().is_empty());
    }
}

/// Valida um alvo de exclusão: IP único ou faixa CIDR.
///
/// Mora aqui, e não na camada da interface, para que o app não precise
/// declarar `ipnet` só para conferir uma string. Validar antes de gravar
/// importa: faixa inválida vira exclusão que não exclui nada, e o usuário só
/// descobre quando a impressora travar no meio da varredura.
pub fn is_valid_target(target: &str) -> bool {
    target.parse::<ipnet::Ipv4Net>().is_ok() || target.parse::<std::net::Ipv4Addr>().is_ok()
}

#[cfg(test)]
mod target_tests {
    use super::is_valid_target;

    #[test]
    fn aceita_ip_e_faixa() {
        assert!(is_valid_target("192.168.1.30"));
        assert!(is_valid_target("192.168.1.0/24"));
        assert!(is_valid_target("10.0.0.0/8"));
    }

    #[test]
    fn recusa_lixo() {
        assert!(!is_valid_target("lixo"));
        assert!(!is_valid_target("192.168.1.300"));
        assert!(!is_valid_target("192.168.1.0/33"));
        assert!(!is_valid_target(""));
    }
}

#[cfg(test)]
mod match_logic_tests {
    // Reproduz o cenário do print de produção: pnet traz os mesmos IPs que o
    // if-addrs, só com nomes NPF diferentes. O casamento por IP tem que achar.
    #[test]
    fn casamento_por_ip_encontra_a_interface_certa() {
        // Simula o que cada lado reporta.
        let ifaddrs = [("Ethernet", "192.168.1.68"), ("Ethernet 2", "192.168.56.1")];
        let pnet = [
            ("\\Device\\NPF_{736E8A2C}", "192.168.1.68"),
            ("\\Device\\NPF_{6ED1EAFD}", "192.168.56.1"),
        ];

        // A pessoa escolheu "Ethernet". Achamos o IP dela no if-addrs...
        let want_ip = ifaddrs.iter().find(|(n, _)| *n == "Ethernet").map(|(_, ip)| *ip).unwrap();
        // ...e casamos esse IP contra o pnet.
        let matched = pnet.iter().find(|(_, ip)| *ip == want_ip).map(|(n, _)| *n);

        assert_eq!(matched, Some("\\Device\\NPF_{736E8A2C}"),
            "o IP 192.168.1.68 tem que casar a Ethernet com seu device NPF");
    }
}