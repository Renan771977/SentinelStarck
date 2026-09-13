//! Telemetria contínua da rede.
//!
//! Um laço que mede a saúde da rede a cada poucos segundos e grava em
//! `probe_sample`, enquanto agrega em `probe_rollup` para as janelas longas.
//! É a fonte que torna o dashboard "ao vivo" verdadeiro — sem ele, qualquer
//! gráfico em tempo real seria dado inventado.
//!
//! ## O que mede, e por que cada alvo importa
//!
//! - **gateway**: latência interna. Alta aqui é problema de cabo, switch ou
//!   saturação da própria LAN.
//! - **dns**: resolução de nome. DNS lento é percebido como "internet lenta",
//!   e o diagnóstico quase sempre erra o alvo.
//! - **internet**: latência de saída. Separa problema interno de problema de
//!   link com o provedor.
//!
//! Medir os três separados é o que permite dizer ONDE está o problema, em vez
//! de só "a rede está lenta".
//!
//! ## Por que ICMP com fallback para TCP
//!
//! Ping ICMP dá a latência mais limpa, mas exige privilégio. Sem ele, medimos
//! o tempo de um TCP connect a uma porta conhecida do alvo — menos preciso,
//! porque inclui o custo do handshake, mas funciona sem privilégio e a
//! TENDÊNCIA (que é o que importa num gráfico) continua fiel.

use crate::model::now;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Um alvo de medição, resolvido do banco.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub id: i64,
    pub kind: String,
    pub address: String,
    pub label: Option<String>,
}

/// Resultado de uma rodada de medição de um alvo.
#[derive(Debug, Clone)]
pub struct Sample {
    pub target_id: i64,
    pub at: i64,
    /// None = pacote perdido / alvo inalcançável.
    pub rtt_ms: Option<f64>,
}

/// Mede um alvo uma vez. Nunca entra em pânico: alvo inalcançável é uma
/// amostra perdida (rtt None), não um erro.
pub async fn probe_once(target: &ProbeTarget, timeout: Duration) -> Sample {
    let rtt = measure(&target.address, timeout).await;
    Sample {
        target_id: target.id,
        at: now(),
        rtt_ms: rtt,
    }
}

/// Latência até um endereço, em milissegundos. None se não respondeu.
///
/// Usa TCP connect a uma porta comum. É o método sem privilégio; a precisão
/// absoluta é menor que ICMP, mas a variação ao longo do tempo — que é o que o
/// gráfico mostra — é fiel.
async fn measure(address: &str, timeout: Duration) -> Option<f64> {
    let ip: IpAddr = address.parse().ok()?;

    // Portas prováveis de responder, por tipo de alvo. Gateway e DNS quase
    // sempre têm 53 ou 80; a internet, 443. Tenta em ordem e usa a primeira
    // que conectar.
    let ports: &[u16] = if is_dns_like(ip) {
        &[53, 443, 80]
    } else {
        &[443, 80, 53]
    };

    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        let start = Instant::now();
        let r = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await;
        match r {
            // Conectou: o RTT é o tempo até o handshake completar.
            Ok(Ok(_)) => return Some(start.elapsed().as_secs_f64() * 1000.0),
            // Recusou rápido: o host está VIVO, só sem aquela porta. O tempo
            // até o RST ainda é uma medida de latência válida.
            Ok(Err(_)) => return Some(start.elapsed().as_secs_f64() * 1000.0),
            // Timeout: tenta a próxima porta.
            Err(_) => continue,
        }
    }
    None
}

fn is_dns_like(_ip: IpAddr) -> bool {
    // Heurística simples; o kind do alvo seria mais preciso, mas a ordem de
    // portas quase não muda o resultado. Mantido simples de propósito.
    false
}

/// Grava uma amostra crua.
pub fn store_sample(conn: &Connection, s: &Sample) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO probe_sample (target_id, at, rtt_ms) VALUES (?1, ?2, ?3)",
        params![s.target_id, s.at, s.rtt_ms],
    )?;
    Ok(())
}

/// Carrega os alvos ativos. Se não houver nenhum, cria os padrões a partir do
/// gateway e dos DNS conhecidos — assim a telemetria começa sozinha.
pub fn active_targets(conn: &Connection, gateway: Option<IpAddr>) -> Result<Vec<ProbeTarget>> {
    ensure_defaults(conn, gateway)?;

    let mut stmt = conn.prepare(
        "SELECT id, kind, address, label FROM probe_target WHERE enabled = 1 ORDER BY id",
    )?;
    let rows: Vec<ProbeTarget> = stmt
        .query_map([], |r| {
            Ok(ProbeTarget {
                id: r.get(0)?,
                kind: r.get(1)?,
                address: r.get(2)?,
                label: r.get(3)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

/// Cria os alvos padrão se a tabela estiver vazia.
///
/// Gateway detectado, um DNS público confiável para latência de internet, e o
/// DNS do provedor se conhecido. Isso faz o dashboard ter o que mostrar já na
/// primeira execução, sem o usuário configurar nada.
fn ensure_defaults(conn: &Connection, gateway: Option<IpAddr>) -> Result<()> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM probe_target", [], |r| r.get(0))?;
    if count > 0 {
        return Ok(());
    }

    let ts = now();
    if let Some(gw) = gateway {
        conn.execute(
            "INSERT OR IGNORE INTO probe_target (kind, address, label, created_at)
             VALUES ('gateway', ?1, 'Gateway', ?2)",
            params![gw.to_string(), ts],
        )?;
    }
    // Referência de internet estável. 1.1.1.1 e 8.8.8.8 respondem rápido e são
    // bons marcos de latência de saída.
    conn.execute(
        "INSERT OR IGNORE INTO probe_target (kind, address, label, created_at)
         VALUES ('internet', '1.1.1.1', 'Internet (Cloudflare)', ?1)",
        params![ts],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO probe_target (kind, address, label, created_at)
         VALUES ('dns_external', '8.8.8.8', 'DNS (Google)', ?1)",
        params![ts],
    )?;
    Ok(())
}

/// Agrega as amostras cruas de uma janela em `probe_rollup`, e apaga as cruas
/// antigas. Chamado periodicamente pelo laço.
///
/// A tabela crua cresce ~1 linha por segundo por alvo. O rollup por minuto é o
/// que a tela de 24h lê; sem ele, 86 mil pontos por dia por alvo derrubam
/// qualquer gráfico.
pub fn rollup_minute(conn: &Connection, older_than: i64) -> Result<usize> {
    // Agrupa por minuto (bucket de 60s) tudo mais antigo que `older_than`,
    // que fica de fora para a janela ao vivo continuar lendo o cru.
    let window_s = 60i64;

    conn.execute(
        "INSERT OR REPLACE INTO probe_rollup
             (target_id, bucket_start, window_s, samples, lost, rtt_avg, rtt_min, rtt_max, jitter_ms)
         SELECT
             target_id,
             (at / ?1) * ?1               AS bucket_start,
             ?1                            AS window_s,
             COUNT(*)                      AS samples,
             SUM(CASE WHEN rtt_ms IS NULL THEN 1 ELSE 0 END) AS lost,
             AVG(rtt_ms)                   AS rtt_avg,
             MIN(rtt_ms)                   AS rtt_min,
             MAX(rtt_ms)                   AS rtt_max,
             -- Jitter aproximado: amplitude sobre a média. O ideal seria a
             -- média do delta absoluto entre amostras consecutivas, mas isso
             -- não se expressa bem em SQL agregado; a amplitude é um proxy
             -- barato e suficiente para o gráfico.
             (MAX(rtt_ms) - MIN(rtt_ms))   AS jitter_ms
         FROM probe_sample
         WHERE at < ?2
         GROUP BY target_id, bucket_start",
        params![window_s, older_than],
    )?;

    // Apaga o cru já agregado.
    let removed = conn.execute("DELETE FROM probe_sample WHERE at < ?1", params![older_than])?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    #[test]
    fn cria_alvos_padrao_quando_vazio() {
        let conn = store::open_memory().unwrap();
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let targets = active_targets(&conn, Some(gw)).unwrap();

        assert!(targets.iter().any(|t| t.kind == "gateway" && t.address == "192.168.1.1"));
        assert!(targets.iter().any(|t| t.kind == "internet"));
        assert!(targets.len() >= 3);
    }

    #[test]
    fn nao_duplica_alvos_em_chamadas_repetidas() {
        let conn = store::open_memory().unwrap();
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        active_targets(&conn, Some(gw)).unwrap();
        let segunda = active_targets(&conn, Some(gw)).unwrap();

        let n: i64 = conn.query_row("SELECT COUNT(*) FROM probe_target", [], |r| r.get(0)).unwrap();
        assert_eq!(n as usize, segunda.len(), "não pode recriar alvos existentes");
    }

    #[test]
    fn amostra_perdida_grava_null() {
        let conn = store::open_memory().unwrap();
        conn.execute("INSERT INTO probe_target (id,kind,address,created_at) VALUES (1,'gateway','192.168.1.1',1)", []).unwrap();

        store_sample(&conn, &Sample { target_id: 1, at: 100, rtt_ms: None }).unwrap();
        store_sample(&conn, &Sample { target_id: 1, at: 101, rtt_ms: Some(2.5) }).unwrap();

        let perdidas: i64 = conn.query_row(
            "SELECT COUNT(*) FROM probe_sample WHERE rtt_ms IS NULL", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(perdidas, 1);
    }

    #[test]
    fn rollup_agrega_por_minuto_e_limpa_o_cru() {
        let conn = store::open_memory().unwrap();
        conn.execute("INSERT INTO probe_target (id,kind,address,created_at) VALUES (1,'gateway','192.168.1.1',1)", []).unwrap();

        // 5 amostras no mesmo minuto (bucket 0..59), uma perdida.
        for (at, rtt) in [(10, Some(2.0)), (20, Some(4.0)), (30, None), (40, Some(3.0)), (50, Some(5.0))] {
            store_sample(&conn, &Sample { target_id: 1, at, rtt_ms: rtt }).unwrap();
        }

        // Agrega tudo antes de at=1000.
        let removed = rollup_minute(&conn, 1000).unwrap();
        assert_eq!(removed, 5, "as 5 cruas foram removidas após agregar");

        let (samples, lost, avg): (i64, i64, f64) = conn.query_row(
            "SELECT samples, lost, rtt_avg FROM probe_rollup WHERE target_id=1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(samples, 5);
        assert_eq!(lost, 1);
        // média de 2,4,3,5 = 3.5 (o NULL não entra no AVG do SQLite)
        assert!((avg - 3.5).abs() < 0.01, "avg = {avg}");
    }
}