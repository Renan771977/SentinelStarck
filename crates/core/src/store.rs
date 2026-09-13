//! Abertura do banco e migrações.
//!
//! Versionamento por `PRAGMA user_version`, sem crate de migração. Com
//! poucos arquivos SQL isso é mais simples de auditar do que qualquer
//! framework, e evita uma dependência.

use anyhow::{anyhow, Result};
use rusqlite::Connection;

/// Reexportado para que os consumidores não precisem declarar rusqlite e
/// arriscar divergir de versão.
pub use rusqlite;
use std::path::Path;

/// Migrações em ordem. Nunca edite uma já aplicada: crie a próxima.
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_initial", include_str!("../migrations/0001_initial.sql")),
    (
        "0002_device_summary_forensics",
        include_str!("../migrations/0002_device_summary_forensics.sql"),
    ),
];

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let conn = Connection::open(path)?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn open_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// Pragmas de conexão.
///
/// `foreign_keys` precisa ser ligado em TODA conexão: o SQLite volta ao padrão
/// desligado a cada abertura, e sem isso as constraints do schema não valem
/// nada. `journal_mode` é persistente e só precisa ser aplicado uma vez, mas
/// repetir é inofensivo.
fn configure(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    let current: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let target = MIGRATIONS.len() as i64;

    if current > target {
        return Err(anyhow!(
            "banco na versão {current}, binário só conhece até {target}. \
             Atualize o aplicativo em vez de abrir com versão antiga."
        ));
    }

    for (i, (name, sql)) in MIGRATIONS.iter().enumerate() {
        let version = (i + 1) as i64;
        if version <= current {
            continue;
        }
        tracing::info!("aplicando migração {name}");
        conn.execute_batch(&format!("BEGIN; {sql} PRAGMA user_version = {version}; COMMIT;"))?;
    }
    Ok(())
}

/// Expurgo das tabelas que crescem sem limite.
///
/// Roda no fim de cada varredura. Sem isso, `observation` e `probe_sample`
/// deixam o banco lento em instalação antiga.
pub fn purge(conn: &Connection) -> Result<usize> {
    let days: i64 = conn
        .query_row(
            "SELECT value FROM setting WHERE key = 'retention.observation_days'",
            [],
            |r| r.get::<_, String>(0),
        )
        .map(|s| s.parse().unwrap_or(30))
        .unwrap_or(30);

    let cutoff = crate::model::now() - days * 86_400;
    let n = conn.execute("DELETE FROM observation WHERE observed_at < ?1", [cutoff])?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migracao_e_idempotente() {
        let conn = open_memory().unwrap();
        let v: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        // Afirma a relação, não o número: assim o teste não quebra a cada
        // migração nova, mas ainda detecta migração que não foi registrada.
        assert_eq!(v, MIGRATIONS.len() as i64);

        // Rodar de novo não deve fazer nada nem falhar.
        migrate(&conn).unwrap();
        let v2: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(v2, v);
    }

    /// A view de resumo precisa expor os campos que a investigação usa.
    #[test]
    fn view_de_resumo_tem_campos_forenses() {
        let conn = open_memory().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM v_device_summary LIMIT 0").unwrap();
        let cols: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
        for c in ["first_seen", "hostname", "ip_history_count", "ip", "mac"] {
            assert!(cols.contains(&c.to_string()), "coluna {c} faltando na view");
        }
    }

    #[test]
    fn foreign_keys_ligadas() {
        let conn = open_memory().unwrap();
        let on: i32 = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0)).unwrap();
        assert_eq!(on, 1);
    }

    #[test]
    fn schema_tem_as_tabelas_principais() {
        let conn = open_memory().unwrap();
        for t in ["device", "device_address", "device_service", "scan", "finding", "change_event"] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "tabela {t} não existe");
        }
    }
}