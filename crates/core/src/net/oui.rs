//! Fabricante a partir do MAC.
//!
//! A base da IEEE vai EMBUTIDA no binário. Consultar API online seria mais
//! simples, mas o produto promete não falar com serviço externo, e promessa
//! desse tipo precisa valer de verdade. A base completa tem ~35 mil linhas e
//! ocupa menos de 1 MB comprimida.
//!
//! Baixe de https://standards-oui.ieee.org/oui/oui.csv e gere o arquivo
//! `oui.tsv` no formato `OUI<TAB>Fabricante` durante o build.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::model::{DeviceKind, Mac};

static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

/// Subconjunto embutido para desenvolvimento. Em produção, troque por
/// include_str!("../../data/oui.tsv") com a base completa.
const SEED: &str = "\
488F5A\tMikroTik
788A20\tUbiquiti Inc
001D09\tDell Inc.
E454E8\tDell Inc.
3C2AF4\tHP Inc.
0011327\tSynology
F01898\tApple, Inc.
BCAD28\tHikvision
50C7BF\tTP-Link
";

fn table() -> &'static HashMap<&'static str, &'static str> {
    TABLE.get_or_init(|| {
        SEED.lines().filter_map(|l| l.split_once('\t')).collect()
    })
}

pub fn vendor(mac: &Mac) -> Option<&'static str> {
    table().get(mac.oui()).copied()
}

/// Palpite de tipo a partir do fabricante.
///
/// Só um palpite, e por isso `kind_source` fica como 'auto' no banco: assim o
/// usuário pode corrigir e a correção nunca é sobrescrita depois.
pub fn guess_kind(vendor: Option<&str>, hostname: Option<&str>) -> DeviceKind {
    let v = vendor.unwrap_or("").to_ascii_lowercase();
    let h = hostname.unwrap_or("").to_ascii_lowercase();

    if v.contains("mikrotik") || v.contains("tp-link") || v.contains("fortinet") {
        return DeviceKind::Router;
    }
    if v.contains("ubiquiti") {
        return if h.contains("ap") || h.contains("unifi") {
            DeviceKind::Ap
        } else {
            DeviceKind::Switch
        };
    }
    if v.contains("hikvision") || v.contains("dahua") || v.contains("foscam") {
        return DeviceKind::Camera;
    }
    if v.contains("hp ") || v.contains("hewlett") || v.contains("brother") || v.contains("epson") {
        return DeviceKind::Printer;
    }
    if v.contains("synology") || v.contains("qnap") {
        return DeviceKind::Nas;
    }
    if v.contains("apple") {
        return DeviceKind::Workstation;
    }
    DeviceKind::Unknown
}

/// Palpite grosseiro de sistema pelo TTL da resposta.
///
/// Custa nada e acerta na maioria. O TTL cai 1 por salto, por isso a faixa em
/// vez do valor exato.
pub fn guess_os_from_ttl(ttl: u8) -> Option<&'static str> {
    match ttl {
        200..=255 => Some("Equipamento de rede"),
        100..=128 => Some("Windows"),
        33..=64 => Some("Linux ou Unix"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_fabricante() {
        let m = Mac::parse("48:8F:5A:12:0C:71").unwrap();
        assert_eq!(vendor(&m), Some("MikroTik"));
    }

    #[test]
    fn palpita_tipo_por_fabricante() {
        assert_eq!(guess_kind(Some("Hikvision"), None), DeviceKind::Camera);
        assert_eq!(guess_kind(Some("Ubiquiti Inc"), Some("ap-2andar")), DeviceKind::Ap);
        assert_eq!(guess_kind(Some("Ubiquiti Inc"), Some("sw-core")), DeviceKind::Switch);
    }

    #[test]
    fn palpita_so_por_ttl() {
        assert_eq!(guess_os_from_ttl(128), Some("Windows"));
        assert_eq!(guess_os_from_ttl(64), Some("Linux ou Unix"));
        assert_eq!(guess_os_from_ttl(255), Some("Equipamento de rede"));
    }
}