//! Teste de ponta a ponta do pipeline, sem rede.
//!
//! Monta o estado de um dispositivo na mão, avalia, persiste, e confere que o
//! ciclo de vida do achado funciona entre varreduras. É o teste que pega
//! regressão em qualquer um dos cinco módulos envolvidos.

use sentinel_core::model::{now, DeviceKind};
use sentinel_core::rules::eval::{self, DeviceState, EvalCoverage, ServiceState};
use sentinel_core::store;
use std::collections::{HashMap, HashSet};

fn svc(port: u16, banner: Option<&str>) -> ServiceState {
    ServiceState {
        protocol: "tcp".into(),
        port,
        service_name: None,
        banner: banner.map(String::from),
        tls_info: None,
    }
}

fn seed(conn: &rusqlite::Connection, id: &str, kind: &str) {
    let ts = now();
    conn.execute(
        "INSERT INTO device (id, kind, identity_confidence, first_seen, last_seen, created_at, updated_at)
         VALUES (?1, ?2, 'high', ?3, ?3, ?3, ?3)",
        rusqlite::params![id, kind, ts],
    ).unwrap();
    conn.execute(
        "INSERT INTO device_address (device_id, kind, value, is_current, first_seen, last_seen)
         VALUES (?1, 'ip', '192.168.1.11', 1, ?2, ?2)",
        rusqlite::params![id, ts],
    ).unwrap();
}

fn full() -> EvalCoverage {
    EvalCoverage { ports_scanned: true, banners_grabbed: true, os_known: true, probes_run: HashSet::new() }
}

/// O servidor legado do protótipo: Windows Server 2012 com SMBv1 e RDP.
#[test]
fn servidor_legado_gera_achados_e_resolve_quando_corrigido() {
    let conn = store::open_memory().unwrap();
    seed(&conn, "srv-legacy", "server");

    let mut state = DeviceState {
        id: "srv-legacy".into(),
        kind: DeviceKind::Server,
        vendor: Some("Dell Inc.".into()),
        os_guess: Some("Windows Server 2012 R2".into()),
        ips: vec!["192.168.1.11".parse().unwrap()],
        services: vec![svc(139, None), svc(445, None), svc(3389, None)],
        probe_hits: HashMap::new(),
        has_credential_consent: false,
    };
    state.probe_hits.insert("smb_v1_negotiated".into(), "dialeto NT LM 0.12 aceito".into());
    state.probe_hits.insert("eol_lookup".into(), "Windows Server 2012 R2 saiu de suporte em 2023-10-10".into());

    let mut cov = full();
    cov.probes_run.insert("smb_v1_negotiated".into());
    cov.probes_run.insert("eol_lookup".into());

    let findings = eval::evaluate(&state, &cov);
    eval::persist(&conn, "srv-legacy", &findings, &cov, now()).unwrap();

    let abertos: i64 = conn.query_row(
        "SELECT COUNT(*) FROM v_open_finding WHERE device_id='srv-legacy'", [], |r| r.get(0)
    ).unwrap();
    assert!(abertos >= 3, "esperado EOL, SMBv1, NetBIOS e RDP; achei {abertos}");

    let criticos: i64 = conn.query_row(
        "SELECT COUNT(*) FROM v_open_finding
          WHERE device_id='srv-legacy' AND severity_effective='critical'", [], |r| r.get(0)
    ).unwrap();
    assert!(criticos >= 1, "EOL de servidor precisa ser crítico");

    // --- o administrador desativa o SMBv1 --------------------------------
    state.probe_hits.remove("smb_v1_negotiated");
    let findings2 = eval::evaluate(&state, &cov);
    let resolved = eval::persist(&conn, "srv-legacy", &findings2, &cov, now() + 3600).unwrap();
    assert!(resolved >= 1, "WIN-001 deveria ter sido resolvido");

    let win001: Option<i64> = conn.query_row(
        "SELECT resolved_at FROM finding WHERE device_id='srv-legacy' AND rule_id='WIN-001'",
        [], |r| r.get(0),
    ).unwrap_or(None);
    assert!(win001.is_some(), "achado resolvido é marcado, não apagado");
}

/// A regressão mais importante: varredura rápida não pode resolver nada que
/// ela não conseguiu avaliar.
#[test]
fn varredura_rapida_nao_resolve_achado_de_porta() {
    let conn = store::open_memory().unwrap();
    seed(&conn, "d1", "switch");

    let state = DeviceState {
        id: "d1".into(), kind: DeviceKind::Switch, vendor: None, os_guess: None,
        ips: vec!["192.168.1.11".parse().unwrap()],
        services: vec![svc(23, Some("Cisco IOS"))],
        probe_hits: HashMap::new(), has_credential_consent: false,
    };

    let f = eval::evaluate(&state, &full());
    eval::persist(&conn, "d1", &f, &full(), now()).unwrap();

    let antes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM v_open_finding WHERE device_id='d1'", [], |r| r.get(0)
    ).unwrap();
    assert!(antes > 0);

    // Agora uma varredura sem portas: estado vazio, cobertura reduzida.
    let magro = DeviceState { services: vec![], ..state.clone() };
    let cov_magra = EvalCoverage { ports_scanned: false, banners_grabbed: false, os_known: false, probes_run: HashSet::new() };

    let f2 = eval::evaluate(&magro, &cov_magra);
    let resolved = eval::persist(&conn, "d1", &f2, &cov_magra, now() + 60).unwrap();

    assert_eq!(resolved, 0, "nada foi avaliado, nada pode ser resolvido");

    let depois: i64 = conn.query_row(
        "SELECT COUNT(*) FROM v_open_finding WHERE device_id='d1'", [], |r| r.get(0)
    ).unwrap();
    assert_eq!(antes, depois, "os achados continuam abertos");
}

/// Aceitação do usuário sobrevive ao achado reaparecer.
#[test]
fn risco_aceito_nao_volta_a_aparecer() {
    let conn = store::open_memory().unwrap();
    seed(&conn, "d1", "switch");

    let state = DeviceState {
        id: "d1".into(), kind: DeviceKind::Switch, vendor: None, os_guess: None,
        ips: vec!["192.168.1.11".parse().unwrap()],
        services: vec![svc(23, Some("Cisco IOS"))],
        probe_hits: HashMap::new(), has_credential_consent: false,
    };

    let f = eval::evaluate(&state, &full());
    eval::persist(&conn, "d1", &f, &full(), now()).unwrap();

    conn.execute(
        "UPDATE finding SET accepted_at = unixepoch(), accepted_by = 'joao',
             accepted_reason = 'switch antigo, troca no orçamento de 2027'
          WHERE device_id = 'd1' AND rule_id = 'NET-001'", [],
    ).unwrap();

    let visivel: i64 = conn.query_row(
        "SELECT COUNT(*) FROM v_open_finding WHERE device_id='d1' AND rule_id='NET-001'",
        [], |r| r.get(0),
    ).unwrap();
    assert_eq!(visivel, 0, "aceito sai da lista principal");

    // Nova varredura reencontra o Telnet. A aceitação precisa sobreviver.
    eval::persist(&conn, "d1", &f, &full(), now() + 3600).unwrap();

    let ainda_aceito: Option<i64> = conn.query_row(
        "SELECT accepted_at FROM finding WHERE device_id='d1' AND rule_id='NET-001'",
        [], |r| r.get(0),
    ).unwrap();
    assert!(ainda_aceito.is_some(), "o usuário já decidiu conviver com isso");
}

/// Valida o padrão de execução usado pela camada Tauri.
///
/// `scan::run` NÃO devolve um future `Send`: a conexão do rusqlite contém
/// `RefCell` e fica viva por cima de vários `.await`. Portanto ela precisa
/// rodar em thread dedicada com runtime de thread única, nunca em
/// `tokio::spawn`. Este teste existe para quebrar se alguém trocar.
#[test]
fn varredura_roda_em_thread_dedicada_com_runtime_proprio() {
    use sentinel_core::model::{PortProfile, ScanConfig};
    use sentinel_core::scan;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!("sentinel-test-{}", std::process::id()));
    let db = dir.join("t.db");
    let cancel = Arc::new(AtomicBool::new(false));

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut conn = store::open(&db).unwrap();
            let cfg = ScanConfig {
                interface: "lo".into(),
                target_cidr: "127.0.0.0/30".into(),
                kind: "quick".into(),
                // Sem fase de portas e com a faixa inteira excluída: o teste
                // valida o encanamento, não a rede.
                port_profile: PortProfile::None,
                exclusions: vec!["127.0.0.0/8".into()],
            };
            let (tx, mut rx) = tokio::sync::mpsc::channel(64);
            let recebidos = tokio::spawn(async move {
                let mut n = 0;
                while rx.recv().await.is_some() {
                    n += 1;
                }
                n
            });
            scan::run(&mut conn, cfg, tx, cancel).await.unwrap();
            recebidos.await.unwrap()
        })
    });

    let eventos = handle.join().expect("a thread de varredura não pode entrar em pânico");
    assert!(eventos > 0, "deveria ter emitido ao menos progresso e conclusão");

    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("sentinel-test-{}", std::process::id())));
}