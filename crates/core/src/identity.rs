//! Transformar observação em identidade estável de dispositivo.
//!
//! Esta é a parte que, se errar, obriga a reescrever o resto. O erro clássico
//! é usar IP ou MAC como chave primária: o IP muda por DHCP e o MAC não é
//! único por dispositivo (Wi-Fi e cabo na mesma máquina, e randomização em
//! celular e notebook moderno).
//!
//! A solução é separar observação de identidade. O dispositivo tem UUID
//! próprio que nunca muda; IP e MAC vivem em `device_address`, N por
//! dispositivo, com marca de qual é o atual.

use crate::model::{Confidence, Mac, Observation};
use rusqlite::{params, Connection, OptionalExtension};

/// Resultado da tentativa de casar uma observação com um dispositivo conhecido.
#[derive(Debug, Clone)]
pub enum Match {
    /// Dispositivo existente reconhecido.
    Existing {
        device_id: String,
        confidence: Confidence,
    },
    /// Nada bateu. Precisa criar dispositivo novo.
    New { confidence: Confidence },
}

/// Aplica a heurística em ordem de prioridade.
///
/// A ordem importa mais que qualquer regra individual: a primeira que casar
/// vence, e as de cima são as mais confiáveis.
pub fn match_observation(conn: &Connection, obs: &Observation) -> rusqlite::Result<Match> {
    // 1. MAC estável conhecido.
    //
    // O caso mais comum e o único realmente confiável. Se o MAC não é
    // randomizado e já está associado a um dispositivo, acabou: IP diferente,
    // hostname diferente, nada disso importa. É a mesma placa de rede.
    if let Some(mac) = &obs.mac {
        if !mac.is_randomized() {
            if let Some(id) = find_by_address(conn, "mac", mac.as_str())? {
                return Ok(Match::Existing {
                    device_id: id,
                    confidence: Confidence::High,
                });
            }
            // MAC estável desconhecido: dispositivo novo, mas com identidade
            // confiável desde o nascimento.
            return Ok(Match::New {
                confidence: Confidence::High,
            });
        }

        // 2. MAC randomizado.
        //
        // Não serve como chave forte: o mesmo celular volta amanhã com outro
        // MAC. Tenta hostname, que costuma persistir mesmo com randomização.
        if let Some(host) = &obs.hostname {
            if let Some(id) = find_by_hostname(conn, host)? {
                return Ok(Match::Existing {
                    device_id: id,
                    confidence: Confidence::Medium,
                });
            }
        }
        return Ok(Match::New {
            confidence: Confidence::Low,
        });
    }

    // 3. Sem MAC.
    //
    // Acontece com tudo que está fora da sub-rede local: atrás de um roteador,
    // todos os hosts aparecem com o MAC do roteador ou sem MAC nenhum. Casar
    // só por IP é frágil, porque o DHCP reaproveita endereço.
    if let Some(ip) = &obs.ip {
        let ip_s = ip.to_string();

        // IP mais hostname juntos são razoavelmente confiáveis.
        if let Some(host) = &obs.hostname {
            if let Some(id) = find_by_ip_and_hostname(conn, &ip_s, host)? {
                return Ok(Match::Existing {
                    device_id: id,
                    confidence: Confidence::Medium,
                });
            }
        }

        // Só IP: aceita, mas marca confiança baixa. O chamador usa isso para
        // NÃO gerar alerta de dispositivo novo com o mesmo peso, senão a lista
        // enche de fantasma toda vez que o DHCP recicla um endereço.
        if let Some(id) = find_by_address(conn, "ip", &ip_s)? {
            return Ok(Match::Existing {
                device_id: id,
                confidence: Confidence::Low,
            });
        }
    }

    Ok(Match::New {
        confidence: Confidence::Low,
    })
}

fn find_by_address(conn: &Connection, kind: &str, value: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT device_id FROM device_address
          WHERE kind = ?1 AND value = ?2 AND is_current = 1
          LIMIT 1",
        params![kind, value],
        |r| r.get(0),
    )
    .optional()
}

fn find_by_hostname(conn: &Connection, hostname: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT id FROM device WHERE hostname = ?1 COLLATE NOCASE LIMIT 1",
        params![hostname],
        |r| r.get(0),
    )
    .optional()
}

fn find_by_ip_and_hostname(
    conn: &Connection,
    ip: &str,
    hostname: &str,
) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT d.id FROM device d
           JOIN device_address a ON a.device_id = d.id
          WHERE a.kind = 'ip' AND a.value = ?1 AND a.is_current = 1
            AND d.hostname = ?2 COLLATE NOCASE
          LIMIT 1",
        params![ip, hostname],
        |r| r.get(0),
    )
    .optional()
}

/// Marca um endereço como atual, tirando o status de quem o tinha antes.
///
/// O índice único parcial do schema garante que só um dispositivo tenha cada
/// endereço como atual. Sem o UPDATE de baixo, o INSERT falharia por violação
/// de constraint quando o DHCP reaproveita um IP.
pub fn set_current_address(
    conn: &Connection,
    device_id: &str,
    kind: &str,
    value: &str,
    ts: i64,
) -> rusqlite::Result<bool> {
    // Alguém mais tinha este endereço como atual?
    let previous: Option<String> = find_by_address(conn, kind, value)?;
    let changed = previous.as_deref().map(|p| p != device_id).unwrap_or(false);

    if changed {
        conn.execute(
            "UPDATE device_address SET is_current = 0 WHERE kind = ?1 AND value = ?2",
            params![kind, value],
        )?;
    }

    // Um dispositivo só tem um IP atual por vez; MACs podem coexistir
    // (Wi-Fi e cabo), então só o IP é exclusivo dentro do dispositivo.
    if kind == "ip" {
        conn.execute(
            "UPDATE device_address SET is_current = 0
              WHERE device_id = ?1 AND kind = 'ip' AND value <> ?2",
            params![device_id, value],
        )?;
    }

    conn.execute(
        "INSERT INTO device_address (device_id, kind, value, is_randomized, is_current, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5)
         ON CONFLICT (device_id, kind, value)
         DO UPDATE SET is_current = 1, last_seen = ?5",
        params![
            device_id,
            kind,
            value,
            if kind == "mac" {
                Mac::parse(value).map(|m| m.is_randomized()).unwrap_or(false) as i32
            } else {
                0
            },
            ts
        ],
    )?;

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Method, Observation};
    use std::net::IpAddr;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../migrations/0001_initial.sql"))
            .unwrap();
        conn
    }

    fn seed_device(conn: &Connection, id: &str, mac: &str, ip: &str, hostname: Option<&str>) {
        let ts = 1_700_000_000i64;
        conn.execute(
            "INSERT INTO device (id, kind, hostname, identity_confidence, first_seen, last_seen, created_at, updated_at)
             VALUES (?1, 'unknown', ?2, 'high', ?3, ?3, ?3, ?3)",
            params![id, hostname, ts],
        )
        .unwrap();
        set_current_address(conn, id, "mac", mac, ts).unwrap();
        set_current_address(conn, id, "ip", ip, ts).unwrap();
    }

    fn obs(ip: Option<&str>, mac: Option<&str>, hostname: Option<&str>) -> Observation {
        Observation {
            ip: ip.map(|s| s.parse::<IpAddr>().unwrap()),
            mac: mac.and_then(Mac::parse),
            hostname: hostname.map(String::from),
            ttl: None,
            rtt_ms: None,
            method: Method::Arp,
            observed_at: 1_700_000_100,
        }
    }

    /// O caso que justifica a arquitetura inteira: o DHCP trocou o IP e o
    /// dispositivo NÃO pode virar um registro novo.
    #[test]
    fn ip_novo_com_mac_conhecido_continua_o_mesmo_dispositivo() {
        let conn = db();
        seed_device(&conn, "dev-1", "A483E71B2C0D", "192.168.1.41", None);

        let m = match_observation(&conn, &obs(Some("192.168.1.77"), Some("a4:83:e7:1b:2c:0d"), None)).unwrap();

        match m {
            Match::Existing { device_id, confidence } => {
                assert_eq!(device_id, "dev-1");
                assert_eq!(confidence, Confidence::High);
            }
            _ => panic!("deveria ter reconhecido o dispositivo pelo MAC"),
        }
    }

    #[test]
    fn mac_randomizado_nao_casa_por_mac() {
        let conn = db();
        seed_device(&conn, "dev-1", "7A11C39E02D4", "192.168.1.50", None);

        // Mesmo IP, MAC randomizado diferente: não deve casar pelo MAC antigo.
        let m = match_observation(&conn, &obs(Some("192.168.1.50"), Some("7E:22:B4:01:99:03"), None)).unwrap();
        assert!(matches!(m, Match::New { confidence: Confidence::Low }));
    }

    #[test]
    fn mac_randomizado_casa_por_hostname() {
        let conn = db();
        seed_device(&conn, "dev-1", "7A11C39E02D4", "192.168.1.50", Some("iphone-joao"));

        let m = match_observation(
            &conn,
            &obs(Some("192.168.1.88"), Some("7E:22:B4:01:99:03"), Some("iphone-joao")),
        )
        .unwrap();

        match m {
            Match::Existing { device_id, confidence } => {
                assert_eq!(device_id, "dev-1");
                assert_eq!(confidence, Confidence::Medium);
            }
            _ => panic!("deveria ter casado pelo hostname"),
        }
    }

    /// DHCP reaproveitou o IP para outra máquina. O endereço precisa migrar
    /// sem violar o índice único parcial.
    #[test]
    fn ip_reaproveitado_migra_de_dispositivo() {
        let conn = db();
        seed_device(&conn, "dev-1", "A483E71B2C0D", "192.168.1.41", None);
        seed_device(&conn, "dev-2", "001D098B3FA2", "192.168.1.42", None);

        let changed = set_current_address(&conn, "dev-2", "ip", "192.168.1.41", 1_700_000_200).unwrap();
        assert!(changed, "deveria sinalizar que o IP trocou de dono");

        let owner = find_by_address(&conn, "ip", "192.168.1.41").unwrap().unwrap();
        assert_eq!(owner, "dev-2");

        // O registro antigo continua existindo como histórico, só não é atual.
        let old: i32 = conn
            .query_row(
                "SELECT is_current FROM device_address
                  WHERE device_id = 'dev-1' AND kind = 'ip' AND value = '192.168.1.41'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old, 0);
    }
}
