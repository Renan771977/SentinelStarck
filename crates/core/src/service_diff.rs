//! Diff de serviços entre varreduras.
//!
//! Separado de `diff.rs` porque roda numa fase diferente: ausência de
//! dispositivo depende do escopo coberto pela varredura inteira, mas abertura
//! de porta depende do escopo coberto *naquele host*. Misturar os dois é como
//! nasce o falso positivo de "todas as portas fecharam" quando a varredura
//! rodou em perfil rápido.

use crate::model::{Change, ChangeType, Severity};
use crate::net::ports::OpenPort;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::collections::HashSet;

/// O que foi efetivamente varrido neste host.
///
/// Sem isso, uma varredura em perfil rápido (4 portas) compararia com o
/// resultado de uma varredura completa (147 portas) e fecharia 143 portas que
/// continuam abertas. É o mesmo bug do `device_gone`, num nível abaixo.
pub struct PortScope {
    pub scanned: HashSet<u16>,
    pub protocol: &'static str,
}

pub fn reconcile(
    conn: &Connection,
    device_id: &str,
    scan_id: &str,
    found: &[OpenPort],
    scope: &PortScope,
    ts: i64,
) -> Result<Vec<Change>> {
    let mut changes = Vec::new();
    let found_set: HashSet<u16> = found.iter().map(|p| p.port).collect();

    // Estado anterior, restrito ao que foi varrido agora.
    let mut stmt = conn.prepare(
        "SELECT port FROM device_service
          WHERE device_id = ?1 AND protocol = ?2 AND closed_at IS NULL",
    )?;
    let previous: HashSet<u16> = stmt
        .query_map(params![device_id, scope.protocol], |r| r.get::<_, u16>(0))?
        .filter_map(Result::ok)
        .filter(|p| scope.scanned.contains(p))
        .collect();

    // Abriu.
    for p in found.iter().filter(|p| !previous.contains(&p.port)) {
        conn.execute(
            "INSERT INTO device_service
                 (device_id, protocol, port, service_name, banner, tls_info, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT (device_id, protocol, port) DO UPDATE SET
                 closed_at = NULL,
                 last_seen = ?7,
                 service_name = COALESCE(?4, service_name),
                 banner = COALESCE(?5, banner),
                 tls_info = COALESCE(?6, tls_info)",
            params![device_id, p.protocol, p.port, p.service_name, p.banner, p.tls_info, ts],
        )?;

        // Porta previsível não merece o mesmo peso. 22 num servidor Linux é
        // rotina; 3389 aparecendo de repente não é.
        let expected = is_baseline(conn, device_id, scope.protocol, p.port)?;

        changes.push(Change {
            device_id: device_id.to_string(),
            change_type: ChangeType::PortOpened,
            severity: if expected { Severity::Info } else { Severity::Medium },
            before: None,
            after: Some(format!(
                "{}/{}{}",
                p.port,
                p.protocol,
                p.service_name.as_deref().map(|s| format!(" ({s})")).unwrap_or_default()
            )),
            detected_at: ts,
        });
    }

    // Fechou.
    for port in previous.iter().filter(|p| !found_set.contains(p)) {
        conn.execute(
            "UPDATE device_service SET closed_at = ?3
              WHERE device_id = ?1 AND protocol = ?4 AND port = ?2 AND closed_at IS NULL",
            params![device_id, port, ts, scope.protocol],
        )?;

        // Porta fechando é quase sempre boa notícia, ou manutenção. Nunca
        // alarma: alertar disso treina o usuário a ignorar a tela de mudanças.
        changes.push(Change {
            device_id: device_id.to_string(),
            change_type: ChangeType::PortClosed,
            severity: Severity::Info,
            before: Some(format!("{port}/{}", scope.protocol)),
            after: None,
            detected_at: ts,
        });
    }

    // Atualiza last_seen de quem continuou aberta, sem gerar mudança.
    for p in found.iter().filter(|p| previous.contains(&p.port)) {
        conn.execute(
            "UPDATE device_service SET last_seen = ?3, banner = COALESCE(?4, banner)
              WHERE device_id = ?1 AND protocol = ?5 AND port = ?2",
            params![device_id, p.port, ts, p.banner, p.protocol],
        )?;
    }

    persist(conn, scan_id, &changes)?;
    Ok(changes)
}

fn is_baseline(conn: &Connection, device_id: &str, protocol: &str, port: u16) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM device_baseline_port
          WHERE device_id = ?1 AND protocol = ?2 AND port = ?3",
        params![device_id, protocol, port],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

fn persist(conn: &Connection, scan_id: &str, changes: &[Change]) -> Result<()> {
    let mut stmt = conn.prepare(
        "INSERT INTO change_event (device_id, scan_id, type, severity, before, after, detected_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for c in changes {
        stmt.execute(params![
            c.device_id, scan_id, c.change_type.as_str(), c.severity.as_str(),
            c.before, c.after, c.detected_at
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(include_str!("../migrations/0001_initial.sql")).unwrap();
        c.execute(
            "INSERT INTO device (id, kind, identity_confidence, first_seen, last_seen, created_at, updated_at)
             VALUES ('d1','server','high',1,1,1,1)", [],
        ).unwrap();
        c.execute(
            "INSERT INTO scan (id, kind, status, interface_name, target_cidr, port_profile, started_at)
             VALUES ('s1','full','completed','eth0','192.168.1.0/24','common',1)", [],
        ).unwrap();
        c
    }

    fn port(p: u16) -> OpenPort {
        OpenPort { port: p, protocol: "tcp", service_name: None, banner: None, tls_info: None }
    }

    fn scope(ports: &[u16]) -> PortScope {
        PortScope { scanned: ports.iter().copied().collect(), protocol: "tcp" }
    }

    #[test]
    fn primeira_varredura_abre_tudo() {
        let c = db();
        let ch = reconcile(&c, "d1", "s1", &[port(22), port(80)], &scope(&[22, 80, 443]), 100).unwrap();
        assert_eq!(ch.len(), 2);
        assert!(ch.iter().all(|x| x.change_type == ChangeType::PortOpened));
    }

    /// O bug que este módulo existe para evitar.
    #[test]
    fn varredura_parcial_nao_fecha_porta_fora_do_escopo() {
        let c = db();
        reconcile(&c, "d1", "s1", &[port(22), port(80), port(3389)], &scope(&[22, 80, 3389]), 100).unwrap();

        // Agora só a 22 foi varrida. As outras não podem ser fechadas.
        let ch = reconcile(&c, "d1", "s1", &[port(22)], &scope(&[22]), 200).unwrap();
        assert!(ch.is_empty(), "nada mudou dentro do escopo varrido");

        let abertas: i64 = c.query_row(
            "SELECT COUNT(*) FROM device_service WHERE device_id='d1' AND closed_at IS NULL",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(abertas, 3, "as três continuam abertas");
    }

    #[test]
    fn porta_que_fecha_gera_mudanca_info() {
        let c = db();
        reconcile(&c, "d1", "s1", &[port(22), port(3389)], &scope(&[22, 3389]), 100).unwrap();
        let ch = reconcile(&c, "d1", "s1", &[port(22)], &scope(&[22, 3389]), 200).unwrap();

        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0].change_type, ChangeType::PortClosed);
        assert_eq!(ch[0].severity, Severity::Info, "fechar porta não é alarme");
    }

    #[test]
    fn porta_da_linha_de_base_nao_alarma() {
        let c = db();
        c.execute(
            "INSERT INTO device_baseline_port (device_id, protocol, port, created_at)
             VALUES ('d1','tcp',22,1)", [],
        ).unwrap();

        let ch = reconcile(&c, "d1", "s1", &[port(22), port(8080)], &scope(&[22, 8080]), 100).unwrap();

        let s22 = ch.iter().find(|c| c.after.as_deref() == Some("22/tcp")).unwrap();
        let s8080 = ch.iter().find(|c| c.after.as_deref() == Some("8080/tcp")).unwrap();

        assert_eq!(s22.severity, Severity::Info, "prevista na linha de base");
        assert_eq!(s8080.severity, Severity::Medium, "não prevista");
    }

    #[test]
    fn porta_que_reabre_volta_a_ficar_aberta() {
        let c = db();
        reconcile(&c, "d1", "s1", &[port(22)], &scope(&[22]), 100).unwrap();
        reconcile(&c, "d1", "s1", &[], &scope(&[22]), 200).unwrap();
        let ch = reconcile(&c, "d1", "s1", &[port(22)], &scope(&[22]), 300).unwrap();

        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0].change_type, ChangeType::PortOpened);

        let n: i64 = c.query_row(
            "SELECT COUNT(*) FROM device_service WHERE device_id='d1' AND port=22",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 1, "reabertura reusa a linha, não cria outra");
    }
}
