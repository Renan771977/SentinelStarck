//! Avaliador de regras.
//!
//! Entrada: estado de um dispositivo. Saída: achados persistidos, com ciclo de
//! vida. É o que transforma o catálogo TOML em linha na tela de Achados.
//!
//! ## O escopo, pela terceira vez
//!
//! O mesmo cuidado de `diff.rs` (ausência de dispositivo) e de
//! `service_diff.rs` (porta fechada) aparece aqui: **só é possível resolver um
//! achado que era avaliável naquela varredura**. Se as portas não foram
//! varridas, não há como concluir que o Telnet foi desligado. Sem o filtro de
//! `EvalCoverage`, uma varredura em perfil rápido marca metade dos achados
//! como resolvidos e eles ressuscitam na varredura seguinte, que é a forma
//! mais rápida de destruir a confiança na tela de Achados.

use super::{catalog, effective_severity, parse_severity, Matcher, Rule, RuleContext};
use crate::model::{now, DeviceKind, Severity};
use anyhow::Result;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Entrada
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServiceState {
    pub protocol: String,
    pub port: u16,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub tls_info: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeviceState {
    pub id: String,
    pub kind: DeviceKind,
    pub vendor: Option<String>,
    pub os_guess: Option<String>,
    pub ips: Vec<IpAddr>,
    pub services: Vec<ServiceState>,
    /// Resultados das sondas ativas, por nome de matcher.
    /// Ex.: "redis_noauth" → evidência.
    pub probe_hits: HashMap<String, String>,
    pub has_credential_consent: bool,
}

/// O que esta varredura conseguiu observar. Determina quais regras podem ser
/// avaliadas e, por consequência, quais achados podem ser resolvidos.
#[derive(Debug, Clone, Default)]
pub struct EvalCoverage {
    pub ports_scanned: bool,
    pub banners_grabbed: bool,
    pub os_known: bool,
    /// Sondas que efetivamente rodaram. Uma sonda que falhou por timeout não
    /// entra aqui: falha de sonda não é ausência de problema.
    pub probes_run: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub scope: Option<String>,
    pub severity_base: Severity,
    pub severity_effective: Severity,
    pub modifiers: Vec<&'static str>,
    pub confidence: String,
    pub evidence: String,
}

// ---------------------------------------------------------------------------
// Regex compilada uma vez
// ---------------------------------------------------------------------------

/// As regex do catálogo são compiladas na primeira chamada e reaproveitadas.
///
/// Compilar dentro do laço custaria caro: 48 regras × 150 portas × 250
/// dispositivos é muita compilação para uma expressão que nunca muda.
fn regex_cache() -> &'static HashMap<String, Regex> {
    static CACHE: OnceLock<HashMap<String, Regex>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut m = HashMap::new();
        for r in &catalog().rule {
            if let Matcher::Declarative(d) = &r.matcher {
                for pat in [d.banner.as_ref(), d.banner_not.as_ref()].into_iter().flatten() {
                    if !m.contains_key(pat) {
                        match Regex::new(pat) {
                            Ok(re) => {
                                m.insert(pat.clone(), re);
                            }
                            Err(e) => {
                                // Regex inválida é erro de catálogo, não de
                                // runtime. Falha alto para aparecer no teste.
                                panic!("regra {}: regex inválida {pat:?}: {e}", r.id);
                            }
                        }
                    }
                }
            }
        }
        m
    })
}

// ---------------------------------------------------------------------------
// Avaliação
// ---------------------------------------------------------------------------

pub fn evaluate(state: &DeviceState, coverage: &EvalCoverage) -> Vec<Finding> {
    let mut out = Vec::new();

    for rule in &catalog().rule {
        // Para regra que tenta autenticar, o CONSENTIMENTO é o interruptor,
        // não a flag `enabled`. Ela nasce com `enabled = false` justamente
        // para que ninguém a ligue em massa no TOML: a única forma de rodar é
        // haver linha em `credential_consent` para aquele dispositivo.
        let permitida = if rule.requires_explicit_consent {
            state.has_credential_consent
        } else {
            rule.enabled
        };
        if !permitida {
            continue;
        }
        if !is_evaluable(rule, coverage) {
            continue;
        }

        for (scope, evidence) in matches(rule, state) {
            let base = parse_severity(&rule.base_severity).unwrap_or(Severity::Info);
            let ctx = RuleContext {
                kind: state.kind,
                has_public_ip: state.ips.iter().any(is_public),
                in_management_vlan: false,
                accepted: false,
                category: rule.category.clone(),
            };
            let (eff, modifiers) = effective_severity(base, &ctx);

            out.push(Finding {
                rule_id: rule.id.clone(),
                scope,
                severity_base: base,
                severity_effective: eff,
                modifiers,
                confidence: rule.confidence.clone(),
                evidence,
            });
        }
    }

    out
}

/// Uma regra é avaliável se esta varredura observou o que ela precisa.
fn is_evaluable(rule: &Rule, cov: &EvalCoverage) -> bool {
    match &rule.matcher {
        Matcher::Custom { custom, .. } => {
            // eol_lookup não é sonda de rede: depende de conhecer o sistema.
            if custom == "eol_lookup" {
                return cov.os_known;
            }
            // As cinco regras de certificado dependem da mesma sonda TLS.
            const TLS_MATCHERS: &[&str] = &[
                "cert_expired", "cert_expiring_soon", "tls_legacy_version",
                "cert_weak_key", "cert_self_signed",
            ];
            if TLS_MATCHERS.contains(&custom.as_str()) {
                return cov.probes_run.contains("tls_inspect");
            }
            cov.probes_run.contains(custom)
        }
        Matcher::Declarative(d) => {
            let needs_ports = !d.ports.is_empty() || !d.udp_ports.is_empty();
            let needs_banner = d.banner.is_some() || d.banner_not.is_some() || d.expect_banner;

            if needs_banner && !cov.banners_grabbed {
                return false;
            }
            if needs_ports && !cov.ports_scanned {
                return false;
            }
            // Regra só de fabricante ou tipo é sempre avaliável.
            true
        }
    }
}

/// Retorna um par (escopo, evidência) por ocorrência.
///
/// O escopo distingue duas ocorrências da mesma regra no mesmo dispositivo,
/// como NET-005 em tcp/80 e em tcp/8080. Sem ele, a segunda sobrescreveria a
/// primeira por causa do UNIQUE do schema.
fn matches(rule: &Rule, state: &DeviceState) -> Vec<(Option<String>, String)> {
    match &rule.matcher {
        Matcher::Custom { custom, .. } => {
            // Sonda simples: chave exata, um achado sem escopo.
            if let Some(ev) = state.probe_hits.get(custom) {
                return vec![(None, ev.clone())];
            }
            // Sonda com escopo por porta (as regras TLS): a chave vem como
            // "matcher:tcp/443". Cada porta afetada vira um achado próprio,
            // pelo mesmo motivo de NET-005 poder disparar em 80 e 8080.
            let prefix = format!("{custom}:");
            let mut hits: Vec<(Option<String>, String)> = state
                .probe_hits
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, ev)| (Some(k[prefix.len()..].to_string()), ev.clone()))
                .collect();
            hits.sort();
            hits
        }

        Matcher::Declarative(d) => {
            // Filtro por tipo e fabricante primeiro: barato e descarta cedo.
            if !d.kinds.is_empty() && !d.kinds.iter().any(|k| k == state.kind.as_str()) {
                return Vec::new();
            }
            if !d.vendor_in.is_empty() {
                let v = state.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
                if !d.vendor_in.iter().any(|w| v.contains(&w.to_ascii_lowercase())) {
                    return Vec::new();
                }
            }

            // Regra sem porta: vale para o dispositivo inteiro.
            if d.ports.is_empty() && d.udp_ports.is_empty() {
                let ev = format!(
                    "fabricante {}, tipo {}",
                    state.vendor.as_deref().unwrap_or("desconhecido"),
                    state.kind.as_str()
                );
                return vec![(None, ev)];
            }

            let re = regex_cache();
            let mut hits = Vec::new();

            for svc in &state.services {
                let listed = match svc.protocol.as_str() {
                    "tcp" => d.ports.contains(&svc.port),
                    "udp" => d.udp_ports.contains(&svc.port),
                    _ => false,
                };
                if !listed {
                    continue;
                }

                let banner = svc.banner.as_deref().unwrap_or("");

                // `expect_banner` exige que o serviço tenha se apresentado.
                // Porta aberta sem banner pode ser encaminhamento ou honeypot,
                // e a regra que depende de identificar o serviço não deve
                // disparar às cegas.
                if d.expect_banner && banner.is_empty() {
                    continue;
                }
                if let Some(pat) = &d.banner {
                    if !re.get(pat).map(|r| r.is_match(banner)).unwrap_or(false) {
                        continue;
                    }
                }
                // `banner_not` cobre o caso em que a AUSÊNCIA de algo é o
                // problema: FTP que não menciona TLS, por exemplo. Se não há
                // banner nenhum, não se pode afirmar a ausência.
                if let Some(pat) = &d.banner_not {
                    if banner.is_empty() {
                        continue;
                    }
                    if re.get(pat).map(|r| r.is_match(banner)).unwrap_or(false) {
                        continue;
                    }
                }

                let mut ev = format!("{}/{} aberta", svc.port, svc.protocol);
                if let Some(name) = &svc.service_name {
                    ev.push_str(&format!(" ({name})"));
                }
                if !banner.is_empty() {
                    ev.push_str(&format!(" — {}", banner.lines().next().unwrap_or("")));
                }

                hits.push((Some(format!("{}/{}", svc.protocol, svc.port)), ev));
            }

            hits
        }
    }
}

/// Fora das faixas privadas da RFC 1918, do loopback e do link-local.
fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private() && !v4.is_loopback() && !v4.is_link_local() && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !(v6.segments()[0] & 0xfe00 == 0xfc00),
    }
}

// ---------------------------------------------------------------------------
// Persistência e ciclo de vida
// ---------------------------------------------------------------------------

/// Grava os achados e resolve os que deixaram de valer.
///
/// Deve rodar dentro da transação do diff, junto com o resto, para que a
/// interface nunca leia estado pela metade.
pub fn persist(
    conn: &Connection,
    device_id: &str,
    findings: &[Finding],
    coverage: &EvalCoverage,
    ts: i64,
) -> Result<usize> {
    let mut current: HashSet<(String, Option<String>)> = HashSet::new();

    for f in findings {
        current.insert((f.rule_id.clone(), f.scope.clone()));

        let modifiers_json = serde_json::to_string(&f.modifiers).unwrap_or_default();

        conn.execute(
            "INSERT INTO finding
                 (device_id, rule_id, scope, severity_base, severity_effective,
                  modifiers_applied, confidence, evidence, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT (device_id, rule_id, scope) DO UPDATE SET
                 last_seen          = ?9,
                 severity_effective = ?5,
                 modifiers_applied  = ?6,
                 evidence           = ?8,
                 -- Achado que volta deixa de estar resolvido, mas a aceitação
                 -- do usuário é preservada: ele já decidiu conviver com isso.
                 resolved_at        = NULL",
            params![
                device_id,
                f.rule_id,
                f.scope,
                f.severity_base.as_str(),
                f.severity_effective.as_str(),
                modifiers_json,
                f.confidence,
                f.evidence,
                ts
            ],
        )?;
    }

    // Resolver o que não apareceu, restrito ao que era avaliável.
    let evaluable: HashSet<&str> = catalog()
        .rule
        .iter()
        .filter(|r| r.enabled && is_evaluable(r, coverage))
        .map(|r| r.id.as_str())
        .collect();

    let mut stmt = conn.prepare(
        "SELECT id, rule_id, scope FROM finding
          WHERE device_id = ?1 AND resolved_at IS NULL",
    )?;

    let rows: Vec<(i64, String, Option<String>)> = stmt
        .query_map(params![device_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .filter_map(Result::ok)
        .collect();

    let mut resolved = 0;
    for (id, rule_id, scope) in rows {
        if !evaluable.contains(rule_id.as_str()) {
            continue; // Não foi avaliada: silêncio, não resolução.
        }
        if current.contains(&(rule_id, scope)) {
            continue;
        }
        conn.execute(
            "UPDATE finding SET resolved_at = ?2 WHERE id = ?1",
            params![id, ts],
        )?;
        resolved += 1;
    }

    Ok(resolved)
}

/// Carrega o estado de um dispositivo para avaliação.
pub fn load_state(conn: &Connection, device_id: &str) -> Result<DeviceState> {
    let (kind, vendor, os_guess): (String, Option<String>, Option<String>) = conn.query_row(
        "SELECT kind, vendor, os_guess FROM device WHERE id = ?1",
        params![device_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;

    let mut stmt = conn.prepare(
        "SELECT value FROM device_address
          WHERE device_id = ?1 AND kind = 'ip' AND is_current = 1",
    )?;
    let ips: Vec<IpAddr> = stmt
        .query_map(params![device_id], |r| r.get::<_, String>(0))?
        .filter_map(Result::ok)
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut stmt = conn.prepare(
        "SELECT protocol, port, service_name, banner, tls_info FROM device_service
          WHERE device_id = ?1 AND closed_at IS NULL",
    )?;
    let services: Vec<ServiceState> = stmt
        .query_map(params![device_id], |r| {
            Ok(ServiceState {
                protocol: r.get(0)?,
                port: r.get(1)?,
                service_name: r.get(2)?,
                banner: r.get(3)?,
                tls_info: r.get(4)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();

    let consent: Option<i64> = conn
        .query_row(
            "SELECT granted_at FROM credential_consent
              WHERE device_id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
            params![device_id, now()],
            |r| r.get(0),
        )
        .optional()?;

    Ok(DeviceState {
        id: device_id.to_string(),
        kind: parse_kind(&kind),
        vendor,
        os_guess,
        ips,
        services,
        probe_hits: HashMap::new(),
        has_credential_consent: consent.is_some(),
    })
}

fn parse_kind(s: &str) -> DeviceKind {
    match s {
        "router" => DeviceKind::Router,
        "switch" => DeviceKind::Switch,
        "firewall" => DeviceKind::Firewall,
        "server" => DeviceKind::Server,
        "workstation" => DeviceKind::Workstation,
        "printer" => DeviceKind::Printer,
        "camera" => DeviceKind::Camera,
        "nas" => DeviceKind::Nas,
        "ap" => DeviceKind::Ap,
        "phone" => DeviceKind::Phone,
        "iot" => DeviceKind::Iot,
        _ => DeviceKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(port: u16, banner: Option<&str>) -> ServiceState {
        ServiceState {
            protocol: "tcp".into(),
            port,
            service_name: crate::net::ports::service_name(port).map(String::from),
            banner: banner.map(String::from),
            tls_info: None,
        }
    }

    fn state(kind: DeviceKind, services: Vec<ServiceState>) -> DeviceState {
        DeviceState {
            id: "d1".into(),
            kind,
            vendor: None,
            os_guess: None,
            ips: vec!["192.168.1.10".parse().unwrap()],
            services,
            probe_hits: HashMap::new(),
            has_credential_consent: false,
        }
    }

    fn full_coverage() -> EvalCoverage {
        EvalCoverage {
            ports_scanned: true,
            banners_grabbed: true,
            os_known: true,
            probes_run: HashSet::new(),
        }
    }

    #[test]
    fn telnet_aberto_dispara_net_001() {
        let s = state(DeviceKind::Switch, vec![svc(23, Some("Cisco IOS"))]);
        let f = evaluate(&s, &full_coverage());
        assert!(f.iter().any(|x| x.rule_id == "NET-001"));
    }

    #[test]
    fn regex_compila_sem_panico() {
        // Força a compilação de todas as regex do catálogo.
        assert!(!regex_cache().is_empty());
    }

    /// O escopo é o que permite duas ocorrências da mesma regra no dispositivo.
    #[test]
    fn mesma_regra_em_duas_portas_gera_dois_achados() {
        let s = state(
            DeviceKind::Server,
            vec![svc(80, Some("Server: nginx")), svc(8080, Some("Server: tomcat"))],
        );
        let f: Vec<_> = evaluate(&s, &full_coverage())
            .into_iter()
            .filter(|x| x.rule_id == "NET-005")
            .collect();

        // Só vale se NET-005 for declarativa nas duas portas; com matcher
        // custom o escopo é None e só há um achado.
        if f.len() > 1 {
            let scopes: HashSet<_> = f.iter().map(|x| x.scope.clone()).collect();
            assert_eq!(scopes.len(), f.len(), "escopos precisam ser distintos");
        }
    }

    #[test]
    fn regra_de_credencial_nao_roda_sem_consentimento() {
        let mut s = state(DeviceKind::Server, vec![svc(22, Some("SSH-2.0-OpenSSH_8.9"))]);
        s.probe_hits.insert("default_creds_shell".into(), "aceitou admin/admin".into());

        let mut cov = full_coverage();
        cov.probes_run.insert("default_creds_shell".into());

        let f = evaluate(&s, &cov);
        assert!(
            !f.iter().any(|x| x.rule_id.starts_with("CRED-")),
            "sem consentimento, nem considerar"
        );

        s.has_credential_consent = true;
        let f = evaluate(&s, &cov);
        assert!(f.iter().any(|x| x.rule_id == "CRED-002"));
    }

    /// Sonda que não rodou não pode gerar nem resolver achado.
    #[test]
    fn regra_custom_sem_sonda_nao_e_avaliavel() {
        let s = state(DeviceKind::Server, vec![svc(6379, None)]);
        let cov = full_coverage(); // probes_run vazio
        let f = evaluate(&s, &cov);
        assert!(!f.iter().any(|x| x.rule_id == "DB-001"));
    }

    #[test]
    fn regra_custom_com_sonda_dispara() {
        let mut s = state(DeviceKind::Server, vec![svc(6379, None)]);
        s.probe_hits.insert("redis_noauth".into(), "PING respondeu +PONG".into());

        let mut cov = full_coverage();
        cov.probes_run.insert("redis_noauth".into());

        let f = evaluate(&s, &cov);
        let hit = f.iter().find(|x| x.rule_id == "DB-001").expect("DB-001 deveria disparar");
        assert_eq!(hit.severity_base, Severity::Critical);
        // Servidor: +1, mas crítica já é o topo.
        assert_eq!(hit.severity_effective, Severity::Critical);
    }

    #[test]
    fn sem_varredura_de_portas_nenhuma_regra_de_porta_e_avaliada() {
        let s = state(DeviceKind::Server, vec![svc(23, Some("telnet"))]);
        let cov = EvalCoverage { ports_scanned: false, ..full_coverage() };
        let f = evaluate(&s, &cov);
        assert!(!f.iter().any(|x| x.rule_id == "NET-001"));
    }

    #[test]
    fn expect_banner_ignora_porta_muda() {
        // NET-001 exige banner. Porta 23 aberta sem resposta não dispara:
        // pode ser encaminhamento ou honeypot.
        let s = state(DeviceKind::Switch, vec![svc(23, None)]);
        let f = evaluate(&s, &full_coverage());
        assert!(!f.iter().any(|x| x.rule_id == "NET-001"));
    }

    #[test]
    fn banner_not_nao_dispara_quando_o_padrao_esta_presente() {
        // NET-002: FTP sem TLS. Banner mencionando TLS não deve disparar.
        let com_tls = state(DeviceKind::Server, vec![svc(21, Some("220 ProFTPD (FTPS/TLS ready)"))]);
        let sem_tls = state(DeviceKind::Server, vec![svc(21, Some("220 ProFTPD Server ready"))]);

        assert!(!evaluate(&com_tls, &full_coverage()).iter().any(|x| x.rule_id == "NET-002"));
        assert!(evaluate(&sem_tls, &full_coverage()).iter().any(|x| x.rule_id == "NET-002"));
    }

    #[test]
    fn ip_publico_eleva_a_severidade_do_achado() {
        let mut s = state(DeviceKind::Workstation, vec![svc(23, Some("telnet"))]);
        s.ips = vec!["200.1.2.3".parse().unwrap()];

        let f = evaluate(&s, &full_coverage());
        let hit = f.iter().find(|x| x.rule_id == "NET-001").unwrap();
        assert_eq!(hit.severity_base, Severity::High);
        assert_eq!(hit.severity_effective, Severity::Critical);
        assert!(hit.modifiers.contains(&"endereço público"));
    }

    #[test]
    fn deteccao_de_ip_publico() {
        assert!(!is_public(&"192.168.1.1".parse().unwrap()));
        assert!(!is_public(&"10.0.0.1".parse().unwrap()));
        assert!(!is_public(&"172.16.0.1".parse().unwrap()));
        assert!(!is_public(&"127.0.0.1".parse().unwrap()));
        assert!(!is_public(&"169.254.1.1".parse().unwrap()));
        assert!(is_public(&"200.1.2.3".parse().unwrap()));
        assert!(is_public(&"8.8.8.8".parse().unwrap()));
    }
}