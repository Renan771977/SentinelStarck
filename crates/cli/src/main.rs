//! CLI do SentinelStack.
//!
//! Parece supérfluo e não é. Vocês vão rodar varredura em rede real dezenas de
//! vezes por dia durante o desenvolvimento, e fazer isso abrindo uma janela e
//! clicando é tortura. Aqui: `sentinel scan 192.168.1.0/24` e o resultado sai
//! em JSON na hora.
//!
//! É também o que permite rodar o núcleo em servidor sem interface no dia em
//! que isso fizer sentido.

use anyhow::{anyhow, Result};
use sentinel_core::{
    model::{PortProfile, ScanConfig},
    scan,
    store::{self, rusqlite},
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    let db_path = std::env::var("SENTINEL_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./sentinel.db"));

    match cmd {
        "scan" => {
            let cidr = args.get(2).ok_or_else(|| anyhow!("uso: sentinel scan <CIDR>"))?;
            let iface = args.get(3).cloned().unwrap_or_else(default_interface);

            let mut conn = store::open(&db_path)?;
            let caps = scan::capabilities(&iface);

            eprintln!("interface  {iface}");
            eprintln!("faixa      {cidr}");
            eprintln!(
                "modo       {}",
                if caps.arp_active { "completo (ARP)" } else { "limitado (TCP + tabela do sistema)" }
            );
            if let Some(r) = &caps.reason {
                eprintln!("aviso      {r}");
            }
            eprintln!();

            let (tx, mut rx) = tokio::sync::mpsc::channel(256);

            let printer = tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    // JSON por linha: fácil de inspecionar com jq e de comparar
                    // entre execuções.
                    println!("{}", serde_json::to_string(&ev).unwrap());
                }
            });

            let cfg = ScanConfig {
                interface: iface,
                target_cidr: cidr.clone(),
                kind: "full".into(),
                port_profile: PortProfile::Common,
                exclusions: load_exclusions(&conn)?,
            };

            // Ctrl+C marca o cancelamento; a varredura encerra na fase atual
            // e o diff roda com `complete = false`, então nada é marcado como
            // ausente nem resolvido indevidamente.
            let cancel = Arc::new(AtomicBool::new(false));
            let c2 = cancel.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("\ncancelando...");
                c2.store(true, Ordering::SeqCst);
            });

            scan::run(&mut conn, cfg, tx, cancel).await?;
            printer.await?;
            store::purge(&conn)?;
        }

        "ifaces" => {
            // Existe porque o nome que a pessoa vê ("Ethernet") não é o nome
            // que o pnet usa no Windows. Aqui ela confere os dois lados.
            for i in sentinel_core::net::iface::list() {
                println!(
                    "{:<28} {:<20} {}",
                    i.name,
                    i.address.unwrap_or_default(),
                    if i.is_loopback { "(loopback)" } else { "" }
                );
            }
            let internos = sentinel_core::net::discover::raw_interface_names();
            if !internos.is_empty() {
                println!("\n--- nome interno usado pelo motor de ARP ---");
                for (nome, ips) in internos {
                    println!("{:<44} {}", nome, ips.join(", "));
                }
            }
        }

        "caps" => {
            let iface = args.get(2).cloned().unwrap_or_else(default_interface);
            println!("{}", serde_json::to_string_pretty(&scan::capabilities(&iface))?);
        }

        "devices" => {
            let conn = store::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT ip, mac, COALESCE(label, hostname, '-'), kind, COALESCE(vendor,'-'),
                        open_ports, finding_count
                   FROM v_device_summary ORDER BY ip",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?;
            for row in rows {
                let (ip, mac, name, kind, vendor, ports, findings) = row?;
                println!(
                    "{:<16} {:<18} {:<22} {:<12} {:<20} {:>3}p {:>3}a",
                    ip.unwrap_or_default(),
                    mac.unwrap_or_default(),
                    name,
                    kind,
                    vendor,
                    ports,
                    findings
                );
            }
        }

        "changes" => {
            let conn = store::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT c.type, c.severity, COALESCE(a.value,'?'), COALESCE(c.after,''), c.detected_at
                   FROM change_event c
                   LEFT JOIN device_address a
                     ON a.device_id = c.device_id AND a.kind='ip' AND a.is_current=1
                  WHERE c.acknowledged_at IS NULL
                  ORDER BY c.detected_at DESC LIMIT 50",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?;
            for row in rows {
                let (t, sev, ip, after, at) = row?;
                println!("{at}  {sev:<8} {t:<16} {ip:<16} {after}");
            }
        }

        _ => {
            eprintln!(
                "sentinel — motor do SentinelStack\n\n\
                 uso:\n  \
                 sentinel scan <CIDR> [interface]   varre e persiste\n  \
                 sentinel devices                  inventário atual\n  \
                 sentinel changes                  mudanças não vistas\n  \
                 sentinel caps [interface]         o que dá para fazer com o privilégio atual\n  \
                 sentinel ifaces                   interfaces disponíveis\n\n\
                 banco: variável SENTINEL_DB (padrão ./sentinel.db)"
            );
        }
    }

    Ok(())
}

fn default_interface() -> String {
    if cfg!(target_os = "windows") { "Ethernet".into() } else { "eth0".into() }
}

fn load_exclusions(conn: &rusqlite::Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT target FROM scan_exclusion")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let list: Vec<String> = rows.filter_map(Result::ok).collect();
    Ok(list)
}