//! Diff entre a varredura atual e o estado anterior.
//!
//! É a razão de o produto existir. Um scanner responde "o que tem na rede";
//! isto responde "o que mudou desde ontem", que é a pergunta que vale dinheiro.

use crate::model::{Change, ChangeType, Severity};
use anyhow::Result;
use rusqlite::{params, Connection};

/// Contexto de uma varredura, usado para decidir o que pode ser comparado.
pub struct ScanScope {
    pub scan_id: String,
    pub target_cidr: String,
    /// A varredura terminou inteira? Se foi cancelada ou falhou, ausência de
    /// dispositivo não significa nada.
    pub complete: bool,
    pub miss_threshold: i32,
}

/// Roda o diff completo. Deve ser chamado **dentro de uma transação**, e o
/// evento `Finished` só pode ser emitido depois do commit. Se emitir antes, a
/// interface lê estado pela metade e pisca.
pub fn run(conn: &Connection, scope: &ScanScope, seen: &[String], ts: i64) -> Result<Vec<Change>> {
    let mut changes = Vec::new();

    // Quem apareceu tem o contador zerado.
    for id in seen {
        let was_missing: i32 = conn.query_row(
            "SELECT miss_count FROM device WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;

        if was_missing >= scope.miss_threshold {
            changes.push(Change {
                device_id: id.clone(),
                change_type: ChangeType::DeviceReturned,
                severity: Severity::Info,
                before: Some("ausente".into()),
                after: Some("online".into()),
                detected_at: ts,
            });
        }

        conn.execute(
            "UPDATE device SET miss_count = 0, last_seen = ?2, last_scan_id = ?3, updated_at = ?2
              WHERE id = ?1",
            params![id, ts, scope.scan_id],
        )?;
    }

    // Ausência só conta se a varredura cobriu o escopo de verdade.
    //
    // Este `if` é o que evita o bug mais comum dessa classe de ferramenta:
    // varredura parcial ou cancelada gerando dezenas de "sumiu" falsos.
    if !scope.complete {
        persist(conn, scope, &changes)?;
        return Ok(changes);
    }

    let missing = find_missing_in_scope(conn, scope, seen)?;

    for id in missing {
        conn.execute(
            "UPDATE device SET miss_count = miss_count + 1, updated_at = ?2 WHERE id = ?1",
            params![id, ts],
        )?;

        let count: i32 = conn.query_row(
            "SELECT miss_count FROM device WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;

        // Exatamente no limite, não a cada varredura depois dele: senão o
        // mesmo dispositivo gera alerta de hora em hora enquanto estiver
        // desligado, e a tela de mudanças vira ruído.
        if count == scope.miss_threshold {
            changes.push(Change {
                device_id: id,
                change_type: ChangeType::DeviceGone,
                severity: Severity::Info,
                before: Some("online".into()),
                after: Some(format!("ausente em {count} varreduras")),
                detected_at: ts,
            });
        }
    }

    persist(conn, scope, &changes)?;
    Ok(changes)
}

/// Dispositivos que deveriam ter aparecido e não apareceram.
///
/// "Deveriam" significa: IP atual dentro da faixa varrida, não ignorado, e
/// visto alguma vez antes. Dispositivo cujo IP está fora do escopo desta
/// varredura simplesmente não é avaliado.
fn find_missing_in_scope(
    conn: &Connection,
    scope: &ScanScope,
    seen: &[String],
) -> Result<Vec<String>> {
    let net: ipnet::Ipv4Net = scope.target_cidr.parse()?;

    let mut stmt = conn.prepare(
        "SELECT d.id, a.value
           FROM device d
           JOIN device_address a ON a.device_id = d.id
          WHERE d.is_ignored = 0 AND a.kind = 'ip' AND a.is_current = 1",
    )?;

    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;

    let mut missing = Vec::new();
    for row in rows {
        let (id, ip) = row?;
        if seen.iter().any(|s| s == &id) {
            continue;
        }
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            if net.contains(&addr) {
                missing.push(id);
            }
        }
    }
    Ok(missing)
}

fn persist(conn: &Connection, scope: &ScanScope, changes: &[Change]) -> Result<()> {
    let mut stmt = conn.prepare(
        "INSERT INTO change_event (device_id, scan_id, type, severity, before, after, detected_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;

    for c in changes {
        stmt.execute(params![
            c.device_id,
            scope.scan_id,
            c.change_type.as_str(),
            c.severity.as_str(),
            c.before,
            c.after,
            c.detected_at,
        ])?;
    }
    Ok(())
}

/// Severidade de "dispositivo novo", conforme o horário.
///
/// Implementa HYG-004 e HYG-005 do catálogo: aparecer às 3h da manhã não é a
/// mesma coisa que aparecer às 14h.
pub fn severity_for_new_device(ts: i64, hours: (u32, u32), weekdays: &[u32]) -> Severity {
    use std::time::{Duration, UNIX_EPOCH};

    let secs_in_day = 86_400i64;
    let day_secs = ts.rem_euclid(secs_in_day);
    let hour = (day_secs / 3600) as u32;

    // 1970-01-01 foi quinta-feira: daí o deslocamento de 4.
    let weekday = (((ts / secs_in_day) + 4) % 7) as u32;
    let _ = UNIX_EPOCH + Duration::from_secs(ts.max(0) as u64);

    let in_hours = hour >= hours.0 && hour < hours.1;
    let in_week = weekdays.contains(&weekday);

    if in_hours && in_week {
        Severity::Info
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/0001_initial.sql"))
            .unwrap();
        conn
    }

    fn seed(conn: &Connection, id: &str, ip: &str, miss: i32) {
        let ts = 1_700_000_000i64;
        conn.execute(
            "INSERT INTO device (id, kind, identity_confidence, miss_count, first_seen, last_seen, created_at, updated_at)
             VALUES (?1, 'unknown', 'high', ?2, ?3, ?3, ?3, ?3)",
            params![id, miss, ts],
        ).unwrap();
        conn.execute(
            "INSERT INTO device_address (device_id, kind, value, is_current, first_seen, last_seen)
             VALUES (?1, 'ip', ?2, 1, ?3, ?3)",
            params![id, ip, ts],
        )
        .unwrap();
    }

    fn scope(complete: bool) -> ScanScope {
        ScanScope {
            scan_id: "s1".into(),
            target_cidr: "192.168.1.0/24".into(),
            complete,
            miss_threshold: 3,
        }
    }

    /// O bug que este código existe para evitar.
    #[test]
    fn varredura_incompleta_nao_marca_ninguem_como_ausente() {
        let conn = db();
        conn.execute(
            "INSERT INTO scan (id, kind, status, interface_name, target_cidr, port_profile, started_at)
             VALUES ('s1','quick','cancelled','eth0','192.168.1.0/24','none',1)",
            [],
        ).unwrap();
        seed(&conn, "dev-1", "192.168.1.10", 2);

        let changes = run(&conn, &scope(false), &[], 1_700_000_100).unwrap();
        assert!(changes.is_empty());

        let miss: i32 = conn
            .query_row("SELECT miss_count FROM device WHERE id='dev-1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(miss, 2, "contador não pode subir em varredura incompleta");
    }

    #[test]
    fn dispositivo_fora_do_escopo_nao_e_avaliado() {
        let conn = db();
        conn.execute(
            "INSERT INTO scan (id, kind, status, interface_name, target_cidr, port_profile, started_at)
             VALUES ('s1','full','completed','eth0','192.168.1.0/24','none',1)",
            [],
        ).unwrap();
        seed(&conn, "dev-outra-vlan", "10.0.0.5", 0);

        run(&conn, &scope(true), &[], 1_700_000_100).unwrap();

        let miss: i32 = conn
            .query_row("SELECT miss_count FROM device WHERE id='dev-outra-vlan'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(miss, 0);
    }

    #[test]
    fn ausencia_so_alerta_ao_cruzar_o_limite() {
        let conn = db();
        conn.execute(
            "INSERT INTO scan (id, kind, status, interface_name, target_cidr, port_profile, started_at)
             VALUES ('s1','full','completed','eth0','192.168.1.0/24','none',1)",
            [],
        ).unwrap();
        seed(&conn, "dev-1", "192.168.1.10", 1);

        // Segunda ausência: ainda em silêncio.
        let c = run(&conn, &scope(true), &[], 1_700_000_100).unwrap();
        assert!(c.is_empty());

        // Terceira: alerta.
        let c = run(&conn, &scope(true), &[], 1_700_000_200).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].change_type, ChangeType::DeviceGone);

        // Quarta: silêncio de novo, senão vira alerta de hora em hora.
        let c = run(&conn, &scope(true), &[], 1_700_000_300).unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn retorno_gera_evento() {
        let conn = db();
        conn.execute(
            "INSERT INTO scan (id, kind, status, interface_name, target_cidr, port_profile, started_at)
             VALUES ('s1','full','completed','eth0','192.168.1.0/24','none',1)",
            [],
        ).unwrap();
        seed(&conn, "dev-1", "192.168.1.10", 5);

        let c = run(&conn, &scope(true), &["dev-1".to_string()], 1_700_000_100).unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].change_type, ChangeType::DeviceReturned);
    }
}
