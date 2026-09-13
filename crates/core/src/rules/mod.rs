//! Motor de regras.
//!
//! Carrega o catálogo TOML embutido no binário, avalia contra o estado do
//! dispositivo e produz achados com severidade calculada.
//!
//! Metade do catálogo é declarativa (porta aberta, regex em banner,
//! fabricante) e é resolvida inteiramente aqui. A outra metade aponta para
//! sondas em `probes.rs`, que precisam conversar com o serviço.

pub mod eval;
pub mod probes;

use crate::model::{DeviceKind, Severity};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Catálogo
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Catalog {
    pub meta: Meta,
    #[serde(default)]
    pub modifier: Vec<Modifier>,
    #[serde(default)]
    pub eol: HashMap<String, toml::value::Datetime>,
    #[serde(default)]
    pub rule: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Meta {
    pub schema: u32,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct Modifier {
    pub when: String,
    pub delta: i32,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub category: String,
    pub base_severity: String,
    pub confidence: String,
    #[serde(rename = "match")]
    pub matcher: Matcher,
    pub why: String,
    pub fix: String,
    #[serde(default)]
    pub refs: Vec<String>,

    /// Regras que tentam autenticar nascem desligadas.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub requires_explicit_consent: bool,
}

fn yes() -> bool { true }

/// Os dois grupos de matcher: o que o TOML resolve sozinho e o que exige
/// sonda ativa.
///
/// A ORDEM AQUI É CRÍTICA. Com `untagged`, o serde tenta as variantes de cima
/// para baixo e aceita a primeira que couber. Como todo campo de `Declarative`
/// tem `default`, ele casa com QUALQUER tabela — inclusive `{ custom = "..." }`,
/// que viraria um Declarative vazio. E Declarative vazio, sem portas, casa com
/// todo dispositivo: o resultado era cada regra de sonda disparando em todo
/// host da rede.
///
/// `Custom` vem primeiro porque exige a chave `custom`, e `Declarative` ganhou
/// `deny_unknown_fields` para não aceitar essa chave nem por acidente.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Matcher {
    Custom { custom: String, #[serde(flatten)] args: HashMap<String, toml::Value> },
    Declarative(Declarative),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declarative {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    /// Regex que o banner deve casar.
    pub banner: Option<String>,
    /// Regex que o banner NÃO deve casar. Usado quando a ausência de algo é o
    /// problema, como FTP sem menção a TLS.
    pub banner_not: Option<String>,
    #[serde(default)]
    pub vendor_in: Vec<String>,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub expect_banner: bool,
}

static CATALOG: OnceLock<Catalog> = OnceLock::new();

/// Carrega e valida o catálogo. Falha na inicialização, não em produção:
/// regra sem `why` ou sem `fix` é erro de programação, e é melhor descobrir no
/// primeiro `cargo test` do que na tela do cliente.
pub fn catalog() -> &'static Catalog {
    CATALOG.get_or_init(|| {
        let raw = include_str!("../../rules.toml");
        let cat: Catalog = toml::from_str(raw).expect("rules.toml inválido");

        for r in &cat.rule {
            assert!(!r.why.trim().is_empty(), "regra {} sem 'why'", r.id);
            assert!(!r.fix.trim().is_empty(), "regra {} sem 'fix'", r.id);
            assert!(
                parse_severity(&r.base_severity).is_some(),
                "regra {} com severidade inválida", r.id
            );
        }
        cat
    })
}

pub fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Severidade efetiva
// ---------------------------------------------------------------------------

/// Contexto do dispositivo usado pelos modificadores.
#[derive(Debug, Default)]
pub struct RuleContext {
    pub kind: DeviceKind,
    pub has_public_ip: bool,
    pub in_management_vlan: bool,
    pub accepted: bool,
    pub category: String,
}

/// Aplica os modificadores à severidade base.
///
/// É isto que faz "RDP no gateway" e "RDP no desktop da contabilidade" serem
/// coisas diferentes usando a mesma regra.
pub fn effective_severity(base: Severity, ctx: &RuleContext) -> (Severity, Vec<&'static str>) {
    let mut delta = 0i32;
    let mut applied = Vec::new();

    if ctx.has_public_ip {
        delta += 2;
        applied.push("endereço público");
    }
    if matches!(ctx.kind, DeviceKind::Router | DeviceKind::Firewall) {
        delta += 1;
        applied.push("equipamento de borda");
    }
    if matches!(ctx.kind, DeviceKind::Server) {
        delta += 1;
        applied.push("servidor");
    }
    if matches!(ctx.kind, DeviceKind::Workstation) && ctx.category == "windows" {
        delta -= 1;
        applied.push("serviço esperado em estação");
    }
    if ctx.in_management_vlan {
        delta -= 1;
        applied.push("VLAN de gerência");
    }
    if ctx.accepted {
        delta -= 2;
        applied.push("risco aceito");
    }

    (shift(base, delta), applied)
}

/// Cada +1 sobe um nível. Saturado nas pontas.
fn shift(s: Severity, delta: i32) -> Severity {
    let rank = match s {
        Severity::Critical => 0, Severity::High => 1, Severity::Medium => 2,
        Severity::Low => 3, Severity::Info => 4,
    };
    // delta positivo = mais grave = rank menor.
    let new = (rank - delta).clamp(0, 4);
    match new {
        0 => Severity::Critical, 1 => Severity::High, 2 => Severity::Medium,
        3 => Severity::Low, _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogo_carrega_e_valida() {
        let c = catalog();
        assert_eq!(c.meta.schema, 1);
        assert!(c.rule.len() >= 40, "esperado catálogo completo, achei {}", c.rule.len());
    }

    /// Se alguém ligar as regras CRED sem pensar, este teste avisa.
    #[test]
    fn regras_de_credencial_nascem_desligadas() {
        for r in catalog().rule.iter().filter(|r| r.id.starts_with("CRED-")) {
            assert!(!r.enabled, "{} não pode nascer habilitada", r.id);
            assert!(r.requires_explicit_consent, "{} precisa exigir consentimento", r.id);
        }
    }

    /// Regressão do bug em que `{ custom = "..." }` era lido como um
    /// Declarative vazio, e portanto casava com todo dispositivo.
    #[test]
    fn matcher_custom_nao_e_lido_como_declarativo() {
        let db001 = catalog().rule.iter().find(|r| r.id == "DB-001").unwrap();
        match &db001.matcher {
            Matcher::Custom { custom, .. } => assert_eq!(custom, "redis_noauth"),
            Matcher::Declarative(_) => panic!("DB-001 precisa ser Custom, não Declarative"),
        }
    }

    /// Nenhuma regra pode ter matcher declarativo totalmente vazio: isso casa
    /// com qualquer dispositivo e enche a tela de achado falso.
    #[test]
    fn nenhuma_regra_declarativa_e_vazia() {
        for r in &catalog().rule {
            if let Matcher::Declarative(d) = &r.matcher {
                let vazio = d.ports.is_empty() && d.udp_ports.is_empty()
                    && d.banner.is_none() && d.banner_not.is_none()
                    && d.vendor_in.is_empty() && d.kinds.is_empty();
                assert!(!vazio, "regra {} tem matcher vazio e casaria com tudo", r.id);
            }
        }
    }

    #[test]
    fn eol_tem_datas_conhecidas() {
        let e = &catalog().eol;
        assert!(e.contains_key("Windows Server 2012 R2"));
        assert!(e.contains_key("CentOS 7"));
    }

    #[test]
    fn rdp_no_gateway_e_mais_grave_que_na_estacao() {
        let base = Severity::Medium;

        let (gw, _) = effective_severity(base, &RuleContext {
            kind: DeviceKind::Router, category: "windows".into(), ..Default::default()
        });
        let (ws, _) = effective_severity(base, &RuleContext {
            kind: DeviceKind::Workstation, category: "windows".into(), ..Default::default()
        });

        assert_eq!(gw, Severity::High);
        assert_eq!(ws, Severity::Low);
    }

    #[test]
    fn ip_publico_eleva_dois_niveis() {
        let (s, why) = effective_severity(Severity::Medium, &RuleContext {
            has_public_ip: true, ..Default::default()
        });
        assert_eq!(s, Severity::Critical);
        assert!(why.contains(&"endereço público"));
    }

    #[test]
    fn severidade_satura_sem_estourar() {
        let (s, _) = effective_severity(Severity::Critical, &RuleContext {
            has_public_ip: true, kind: DeviceKind::Router, ..Default::default()
        });
        assert_eq!(s, Severity::Critical, "não existe nível acima de crítica");

        let (s, _) = effective_severity(Severity::Info, &RuleContext {
            accepted: true, ..Default::default()
        });
        assert_eq!(s, Severity::Info);
    }
}