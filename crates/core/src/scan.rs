//! Orquestração da varredura.
//!
//! Cinco fases, em ordem obrigatória:
//!
//! 1. **Descoberta** — quem está na rede (ARP ou tabela do sistema).
//! 2. **Resolução** — nome, fabricante, identidade estável.
//! 3. **Portas** — serviços, banner e sondas ativas.
//! 4. **Regras** — avaliação do catálogo.
//! 5. **Diff** — comparação com o estado anterior.
//!
//! A ordem não é arbitrária. A fase 2 precisa vir antes da 3 porque é ela que
//! descobre que 192.168.1.30 é uma impressora HP, e isso muda o ritmo com que
//! a fase 3 pode tocar naquele host. Varrer antes de identificar é como se
//! imprime trinta páginas em branco no financeiro do cliente.
//!
//! As fases 4 e 5 rodam numa transação única, e o evento de conclusão só sai
//! depois do commit: se sair antes, a interface lê estado pela metade e pisca.

use crate::diff::{self, ScanScope};
use crate::identity::{self, Match};
use crate::model::*;
use crate::net::{discover, oui, ports, resolve};
use crate::rules::{eval, probes};
use crate::service_diff::{self, PortScope};
use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;
use rusqlite::{params, Connection};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc::Sender, Semaphore};

/// Teto global de conexões simultâneas em toda a varredura.
///
/// Independente do limite por host. Este protege a rede e a tabela de conexões
/// do próprio sistema operacional; o de `ports::pacing_for` protege cada
/// equipamento individualmente. Os dois são necessários: um semáforo global
/// generoso pode jogar 256 conexões na mesma impressora.
const GLOBAL_CONCURRENCY: usize = 256;

// ---------------------------------------------------------------------------
// Capacidades
// ---------------------------------------------------------------------------

/// Tentar e falhar é mais confiável que checar permissão por plataforma:
/// `CAP_NET_RAW` presente não garante que a interface aceite canal de enlace,
/// e no Windows a presença do Npcap não é visível por permissão.
///
/// A mensagem de `reason` distingue três situações diferentes, porque
/// confundi-las custa horas: interface não resolvida, biblioteca ausente e
/// permissão insuficiente pedem correções completamente distintas.
pub fn capabilities(iface: &str) -> Capabilities {
    let (arp, reason) = probe_raw_socket(iface);
    Capabilities {
        arp_active: arp,
        passive_listen: arp,
        tcp_connect: true,
        icmp: arp,
        reason,
    }
}

/// Retorna se o canal de enlace abre, e o motivo quando não abre.
#[cfg(feature = "raw-socket")]
fn probe_raw_socket(iface: &str) -> (bool, Option<String>) {
    use pnet::datalink;

    let Some(found) = discover::resolve_interface(iface) else {
        // Não é falta de permissão: o nome simplesmente não corresponde a
        // nenhuma interface. `sentinel ifaces` mostra os nomes válidos.
        return (
            false,
            Some(format!(
                "Interface '{iface}' não encontrada. Rode `sentinel ifaces` para ver os nomes disponíveis."
            )),
        );
    };

    match datalink::channel(&found, Default::default()) {
        Ok(_) => (true, None),
        Err(e) => {
            let detalhe = if cfg!(target_os = "windows") {
                "Verifique se o Npcap está instalado e, se marcou a opção de restringir o acesso a administradores, rode o aplicativo como administrador."
            } else {
                "Rode `sudo setcap cap_net_raw,cap_net_admin+eip` no executável para liberar ARP e escuta passiva."
            };
            (false, Some(format!("Não foi possível abrir o canal de enlace em '{}': {e}. {detalhe}", found.name)))
        }
    }
}

#[cfg(not(feature = "raw-socket"))]
fn probe_raw_socket(_iface: &str) -> (bool, Option<String>) {
    (
        false,
        Some(
            "Compilado sem o recurso `raw-socket`. A descoberta usa TCP e a tabela do sistema, que encontra menos dispositivos."
                .into(),
        ),
    )
}

// ---------------------------------------------------------------------------
// Execução
// ---------------------------------------------------------------------------

/// Estado de um host carregado entre as fases 2 e 3.
struct HostWork {
    device_id: String,
    ip: IpAddr,
    kind: DeviceKind,
    vendor: Option<String>,
    os_guess: Option<String>,
}

struct Summary {
    found: usize,
    new: usize,
    gone: usize,
}

pub async fn run(
    conn: &mut Connection,
    cfg: ScanConfig,
    tx: Sender<ScanEvent>,
    cancel: Arc<AtomicBool>,
) -> Result<String> {
    let scan_id = uuid::Uuid::new_v4().to_string();
    let net: Ipv4Net = cfg
        .target_cidr
        .parse()
        .map_err(|_| anyhow!("faixa inválida: {}", cfg.target_cidr))?;

    let caps = capabilities(&cfg.interface);

    conn.execute(
        "INSERT INTO scan (id, kind, status, interface_name, target_cidr, port_profile, privileged, started_at)
         VALUES (?1, ?2, 'running', ?3, ?4, ?5, ?6, ?7)",
        params![
            scan_id, cfg.kind, cfg.interface, cfg.target_cidr,
            cfg.port_profile.as_str(), caps.arp_active as i32, now()
        ],
    )?;
    audit(conn, "scan.start", Some(&scan_id), &cfg.target_cidr)?;

    // A exclusão é resolvida aqui e desce como closure até a camada mais
    // baixa. Se fosse checada só na interface, um dia alguém chama a função
    // direto e a impressora imprime.
    let excluded = build_exclusion_filter(&cfg.exclusions);

    match execute_phases(conn, &cfg, &scan_id, net, &caps, &excluded, &tx, &cancel).await {
        Ok(s) => {
            let _ = tx
                .send(ScanEvent::Finished {
                    scan_id: scan_id.clone(),
                    found: s.found,
                    new: s.new,
                    gone: s.gone,
                })
                .await;
            Ok(scan_id)
        }
        Err(e) => {
            let _ = conn.execute(
                "UPDATE scan SET status='failed', finished_at=?2, error=?3 WHERE id=?1",
                params![scan_id, now(), e.to_string()],
            );
            let _ = tx
                .send(ScanEvent::Failed {
                    scan_id: scan_id.clone(),
                    error: e.to_string(),
                })
                .await;
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_phases(
    conn: &mut Connection,
    cfg: &ScanConfig,
    scan_id: &str,
    net: Ipv4Net,
    caps: &Capabilities,
    excluded: &dyn Fn(Ipv4Addr) -> bool,
    tx: &Sender<ScanEvent>,
    cancel: &AtomicBool,
) -> Result<Summary> {
    let progress = |phase: ScanPhase, done: usize, total: usize| ScanEvent::Progress {
        scan_id: scan_id.to_string(),
        phase,
        done,
        total,
    };

    // ---- Fase 1: descoberta ------------------------------------------------

    let _ = tx.send(progress(ScanPhase::Discovery, 0, net.hosts().count())).await;

    let observations = if caps.arp_active {
        discover_privileged(cfg, net, excluded)?
    } else {
        let txp = tx.clone();
        let sid = scan_id.to_string();
        discover::neighbor_sweep(net, excluded, GLOBAL_CONCURRENCY, move |done, total| {
            let _ = txp.try_send(ScanEvent::Progress {
                scan_id: sid.clone(),
                phase: ScanPhase::Discovery,
                done,
                total,
            });
        })
        .await?
    };

    if cancel.load(Ordering::SeqCst) {
        return finish_cancelled(conn, scan_id);
    }

    // ---- Fase 2: resolução e identidade ------------------------------------
    //
    // Precisa terminar antes da fase de portas: é aqui que se descobre que
    // aquele IP é uma impressora, e portanto que ela merece ritmo delicado.

    let total = observations.len();
    let mut work: Vec<HostWork> = Vec::with_capacity(total);
    let mut new_count = 0usize;

    for (i, mut obs) in observations.into_iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        if let Some(ip) = obs.ip {
            obs.hostname = resolve::reverse_dns(ip, Duration::from_millis(400)).await;
        }

        let dbtx = conn.transaction()?;
        let (device, is_new) = upsert(&dbtx, &obs, scan_id)?;
        dbtx.commit()?;

        if is_new {
            new_count += 1;
        }
        if let Some(ip) = obs.ip {
            work.push(HostWork {
                device_id: device.id.clone(),
                ip,
                kind: device.kind,
                vendor: device.vendor.clone(),
                os_guess: device.os_guess.clone(),
            });
        }

        let _ = tx
            .send(ScanEvent::Device {
                scan_id: scan_id.to_string(),
                device,
                is_new,
            })
            .await;
        let _ = tx.send(progress(ScanPhase::Resolution, i + 1, total)).await;
    }

    // ---- Fase 3: portas, banner e sondas -----------------------------------

    let port_list: &[u16] = match cfg.port_profile {
        PortProfile::None => &[],
        PortProfile::Common | PortProfile::Extended => ports::PROFILE_COMMON,
    };

    // A cobertura é montada aqui e carregada até a fase 4. É ela que impede
    // que uma varredura sem portas resolva achado baseado em porta.
    let coverage_base = eval::EvalCoverage {
        ports_scanned: !port_list.is_empty(),
        banners_grabbed: !port_list.is_empty(),
        os_known: false,
        probes_run: HashSet::new(),
    };

    let global = Arc::new(Semaphore::new(GLOBAL_CONCURRENCY));
    let mut scanned: Vec<(usize, Vec<ports::OpenPort>, _, _)> = Vec::new();

    if !port_list.is_empty() {
        for (i, host) in work.iter().enumerate() {
            if cancel.load(Ordering::SeqCst) {
                break;
            }

            let target = ports::HostTarget {
                ip: host.ip,
                kind: host.kind,
                vendor: host.vendor.clone(),
                baseline: load_baseline(conn, &host.device_id)?,
            };

            let open = ports::scan_host(&target, port_list, global.clone(), true).await;
            let open_nums: Vec<u16> = open.iter().map(|p| p.port).collect();

            // Sonda ativa só onde a porta respondeu. Economiza tempo e evita
            // conexão inútil no log do cliente.
            let (hits, ran) = probes::run_for_host(
                host.ip,
                &open_nums,
                host.os_guess.as_deref(),
                Duration::from_millis(1200),
            )
            .await;

            scanned.push((i, open, hits, ran));
            let _ = tx.send(progress(ScanPhase::Ports, i + 1, work.len())).await;
        }
    }

    // ---- Fases 4 e 5: regras e diff, transação única -----------------------

    let _ = tx.send(progress(ScanPhase::Rules, 0, scanned.len().max(1))).await;

    let threshold: i32 = setting(conn, "device.miss_threshold")?
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    let ts = now();
    let complete = !cancel.load(Ordering::SeqCst);
    let seen_ids: Vec<String> = work.iter().map(|h| h.device_id.clone()).collect();
    let port_scope: HashSet<u16> = port_list.iter().copied().collect();

    let dbtx = conn.transaction()?;

    for (idx, open, hits, ran) in &scanned {
        let host = &work[*idx];

        service_diff::reconcile(
            &dbtx,
            &host.device_id,
            scan_id,
            open,
            &PortScope {
                scanned: port_scope.clone(),
                protocol: "tcp",
            },
            ts,
        )?;

        let mut state = eval::load_state(&dbtx, &host.device_id)?;
        state.probe_hits = hits.clone();

        let mut cov = coverage_base.clone();
        cov.probes_run = ran.clone();
        cov.os_known = host.os_guess.is_some();

        let findings = eval::evaluate(&state, &cov);
        eval::persist(&dbtx, &host.device_id, &findings, &cov, ts)?;
    }

    let changes = diff::run(
        &dbtx,
        &ScanScope {
            scan_id: scan_id.to_string(),
            target_cidr: cfg.target_cidr.clone(),
            complete,
            miss_threshold: threshold,
        },
        &seen_ids,
        ts,
    )?;

    let gone = changes
        .iter()
        .filter(|c| c.change_type == ChangeType::DeviceGone)
        .count();

    dbtx.execute(
        "UPDATE scan SET status=?2, finished_at=?3, device_count=?4, new_count=?5, gone_count=?6
          WHERE id=?1",
        params![
            scan_id,
            if complete { "completed" } else { "cancelled" },
            now(),
            seen_ids.len(),
            new_count,
            gone
        ],
    )?;
    dbtx.commit()?;

    Ok(Summary {
        found: seen_ids.len(),
        new: new_count,
        gone,
    })
}

fn finish_cancelled(conn: &Connection, scan_id: &str) -> Result<Summary> {
    conn.execute(
        "UPDATE scan SET status='cancelled', finished_at=?2 WHERE id=?1",
        params![scan_id, now()],
    )?;
    Ok(Summary { found: 0, new: 0, gone: 0 })
}

#[cfg(feature = "raw-socket")]
fn discover_privileged(
    cfg: &ScanConfig,
    net: Ipv4Net,
    excluded: &dyn Fn(Ipv4Addr) -> bool,
) -> Result<Vec<Observation>> {
    let mut out = Vec::new();
    discover::arp_sweep(&cfg.interface, net, excluded, &mut |o| out.push(o))?;
    Ok(out)
}

#[cfg(not(feature = "raw-socket"))]
fn discover_privileged(
    _cfg: &ScanConfig,
    _net: Ipv4Net,
    _excluded: &dyn Fn(Ipv4Addr) -> bool,
) -> Result<Vec<Observation>> {
    Err(anyhow!("build sem o recurso raw-socket"))
}

// ---------------------------------------------------------------------------
// Persistência de dispositivo
// ---------------------------------------------------------------------------

fn upsert(conn: &Connection, obs: &Observation, scan_id: &str) -> Result<(Device, bool)> {
    let ts = obs.observed_at;
    let vendor = obs.mac.as_ref().and_then(oui::vendor);
    let os_guess = obs.ttl.and_then(oui::guess_os_from_ttl);

    let (device_id, is_new) = match identity::match_observation(conn, obs)? {
        Match::Existing { device_id, .. } => (device_id, false),
        Match::New { confidence } => {
            let id = uuid::Uuid::new_v4().to_string();
            let kind = oui::guess_kind(vendor, obs.hostname.as_deref());
            conn.execute(
                "INSERT INTO device (id, kind, kind_source, vendor, hostname, os_guess,
                                     identity_confidence, first_seen, last_seen, last_scan_id,
                                     created_at, updated_at)
                 VALUES (?1, ?2, 'auto', ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?7, ?7)",
                params![id, kind.as_str(), vendor, obs.hostname, os_guess,
                        confidence.as_str(), ts, scan_id],
            )?;
            (id, true)
        }
    };

    if let Some(mac) = &obs.mac {
        identity::set_current_address(conn, &device_id, "mac", mac.as_str(), ts)?;
    }
    if let Some(ip) = &obs.ip {
        identity::set_current_address(conn, &device_id, "ip", &ip.to_string(), ts)?;
    }

    // COALESCE preserva o que já existe: dado automático só entra onde havia
    // lacuna. Campo fixado pelo usuário nunca é tocado.
    conn.execute(
        "UPDATE device
            SET hostname   = COALESCE(?2, hostname),
                vendor     = COALESCE(?3, vendor),
                os_guess   = COALESCE(?4, os_guess),
                last_seen  = ?5,
                updated_at = ?5
          WHERE id = ?1",
        params![device_id, obs.hostname, vendor, os_guess, ts],
    )?;

    conn.execute(
        "INSERT INTO observation (scan_id, device_id, ip, mac, hostname, ttl, rtt_ms, method, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            scan_id, device_id,
            obs.ip.map(|i| i.to_string()),
            obs.mac.as_ref().map(|m| m.as_str()),
            obs.hostname, obs.ttl, obs.rtt_ms,
            obs.method.as_str(), ts
        ],
    )?;

    Ok((load_device(conn, &device_id)?, is_new))
}

fn load_device(conn: &Connection, id: &str) -> Result<Device> {
    Ok(conn.query_row(
        "SELECT id, label, label_pinned, kind, kind_source, vendor, hostname, os_guess,
                identity_confidence, first_seen, last_seen, miss_count, is_ignored
           FROM device WHERE id = ?1",
        params![id],
        |r| {
            Ok(Device {
                id: r.get(0)?,
                label: r.get(1)?,
                label_pinned: r.get::<_, i32>(2)? == 1,
                kind: parse_kind(&r.get::<_, String>(3)?),
                kind_source: r.get(4)?,
                vendor: r.get(5)?,
                hostname: r.get(6)?,
                os_guess: r.get(7)?,
                identity_confidence: match r.get::<_, String>(8)?.as_str() {
                    "high" => Confidence::High,
                    "medium" => Confidence::Medium,
                    _ => Confidence::Low,
                },
                first_seen: r.get(9)?,
                last_seen: r.get(10)?,
                miss_count: r.get(11)?,
                is_ignored: r.get::<_, i32>(12)? == 1,
            })
        },
    )?)
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

fn load_baseline(conn: &Connection, device_id: &str) -> Result<HashSet<u16>> {
    let mut stmt = conn
        .prepare("SELECT port FROM device_baseline_port WHERE device_id = ?1 AND protocol = 'tcp'")?;
    // O resultado precisa ser materializado numa variável ANTES do return.
    // Devolver o iterador direto no `Ok(...)` cria um temporário que empresta
    // `stmt`, e `stmt` é destruído primeiro: é o erro E0597.
    let ports: HashSet<u16> = stmt
        .query_map(params![device_id], |r| r.get::<_, u16>(0))?
        .filter_map(Result::ok)
        .collect();
    Ok(ports)
}

// ---------------------------------------------------------------------------
// Auxiliares
// ---------------------------------------------------------------------------

fn build_exclusion_filter(list: &[String]) -> impl Fn(Ipv4Addr) -> bool {
    let nets: Vec<Ipv4Net> = list
        .iter()
        .filter_map(|s| {
            s.parse::<Ipv4Net>().ok().or_else(|| {
                s.parse::<Ipv4Addr>().ok().and_then(|a| Ipv4Net::new(a, 32).ok())
            })
        })
        .collect();
    move |ip| nets.iter().any(|n| n.contains(&ip))
}

fn setting(conn: &Connection, key: &str) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    Ok(conn
        .query_row("SELECT value FROM setting WHERE key = ?1", params![key], |r| r.get(0))
        .optional()?)
}

fn audit(conn: &Connection, action: &str, target: Option<&str>, detail: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_log (at, actor, action, target_type, target_id, detail)
         VALUES (?1, ?2, ?3, 'scan', ?4, ?5)",
        params![
            now(),
            std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default(),
            action,
            target,
            detail
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusao_aceita_ip_e_cidr() {
        let lista = vec!["192.168.1.30".to_string(), "192.168.1.200/29".to_string()];
        let f = build_exclusion_filter(&lista);
        assert!(f("192.168.1.30".parse().unwrap()));
        assert!(f("192.168.1.201".parse().unwrap()));
        assert!(!f("192.168.1.31".parse().unwrap()));
    }

    #[test]
    fn exclusao_ignora_entrada_invalida_sem_quebrar() {
        let lista = vec!["lixo".to_string(), "192.168.1.30".to_string()];
        let f = build_exclusion_filter(&lista);
        assert!(f("192.168.1.30".parse().unwrap()));
    }

    /// O contrato entre a fase 3 e a fase 4: perfil sem portas precisa
    /// produzir cobertura que impeça resolução de achado de porta.
    #[test]
    fn perfil_none_nao_marca_portas_como_varridas() {
        let lista: &[u16] = match PortProfile::None {
            PortProfile::None => &[],
            _ => ports::PROFILE_COMMON,
        };
        assert!(lista.is_empty());

        let cov = eval::EvalCoverage {
            ports_scanned: !lista.is_empty(),
            ..Default::default()
        };
        assert!(!cov.ports_scanned);
    }
}