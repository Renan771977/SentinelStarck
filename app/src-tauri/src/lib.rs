//! Camada Tauri: a única coisa que conhece interface.
//!
//! Não há lógica de rede nem de banco aqui. Este arquivo traduz: comando do
//! frontend vira chamada ao núcleo, evento do núcleo vira `emit` para o
//! frontend. Se alguma regra de negócio aparecer neste arquivo, ela está no
//! lugar errado.
//!
//! ## Por que cada comando abre a própria conexão
//!
//! `rusqlite::Connection` não é `Sync`. A tentação é guardar uma conexão em
//! `Mutex` no estado, mas aí a varredura segura o lock por 60 segundos e todo
//! comando de leitura trava: a tela congela justamente durante a varredura,
//! que é quando o usuário mais está olhando.
//!
//! Abrir conexão SQLite custa microssegundos, e o modo WAL permite vários
//! leitores simultâneos com um escritor. Então o estado guarda só o caminho do
//! arquivo, e cada comando abre e fecha a sua.

use sentinel_core::model::{Capabilities, PortProfile, ScanConfig, ScanEvent};
use sentinel_core::net::iface::{self, InterfaceInfo};
// Reexportado pela core: garante versão única do rusqlite em todo o projeto.
use sentinel_core::store::rusqlite;
use sentinel_core::{scan, store};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};

// ---------------------------------------------------------------------------
// Estado
// ---------------------------------------------------------------------------

pub struct AppState {
    db_path: PathBuf,
    /// Só uma varredura por vez. Tentar duas ao mesmo tempo na mesma interface
    /// gera colisão de ARP e resultado inconsistente.
    scanning: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
}

impl AppState {
    fn conn(&self) -> Result<rusqlite::Connection, String> {
        store::open(&self.db_path).map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tipos de saída
// ---------------------------------------------------------------------------

/// Uma linha da tela de Dispositivos.
///
/// Espelha a view `v_device_summary`, que já devolve tudo pronto: sem isso,
/// a lista faria uma consulta por dispositivo para contar portas e achados,
/// que é o clássico N+1.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRow {
    pub id: String,
    pub label: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub kind: String,
    pub vendor: Option<String>,
    pub os_guess: Option<String>,
    pub identity_confidence: String,
    pub last_seen: i64,
    pub miss_count: i32,
    pub open_ports: i64,
    pub finding_count: i64,
    /// 0 = crítica … 4 = info, NULL quando não há achado aberto.
    /// É o que pinta a barra de 3px na borda esquerda da linha.
    pub worst_severity_rank: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRow {
    pub id: i64,
    pub device_id: String,
    pub device_ip: Option<String>,
    pub device_label: Option<String>,
    pub change_type: String,
    pub severity: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub detected_at: i64,
    pub acknowledged: bool,
}


#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub why: String,
    pub fix: String,
    pub enabled: bool,
    pub requires_consent: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressInfo {
    pub kind: String,
    pub value: String,
    pub is_current: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub protocol: String,
    pub port: u16,
    pub service_name: Option<String>,
    pub banner: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingInfo {
    pub id: i64,
    pub device_id: String,
    pub device_ip: Option<String>,
    pub rule_id: String,
    pub scope: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub evidence: Option<String>,
    pub first_seen: i64,
    pub accepted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDetail {
    pub id: String,
    pub label: Option<String>,
    pub kind: String,
    pub vendor: Option<String>,
    pub os_guess: Option<String>,
    pub hostname: Option<String>,
    pub identity_confidence: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub notes: Option<String>,
    pub addresses: Vec<AddressInfo>,
    pub services: Vec<ServiceInfo>,
    pub findings: Vec<FindingInfo>,
}

// ---------------------------------------------------------------------------
// Comandos
// ---------------------------------------------------------------------------

/// O que dá para fazer com o privilégio atual.
///
/// A interface chama isto na inicialização e desabilita botão com explicação,
/// em vez de deixar o usuário clicar e receber erro.
#[tauri::command]
fn get_capabilities(interface: String) -> Capabilities {
    scan::capabilities(&interface)
}

/// Interfaces disponíveis para varredura.
///
/// Delegado à core, que usa `if-addrs` em vez de `pnet`. Isso importa: se
/// dependesse do pnet, o modo limitado devolveria lista vazia e o botão de
/// escanear ficaria permanentemente desabilitado justamente para quem não tem
/// o SDK do Npcap instalado.
#[tauri::command]
fn list_interfaces() -> Vec<InterfaceInfo> {
    iface::list()
}

/// Dispara a varredura e retorna imediatamente.
///
/// Nada de devolver o array no fim: os dispositivos chegam um a um pelo evento
/// `scan:device`. Uma /24 leva de 30 a 60 segundos, e a diferença entre uma
/// tela vazia com spinner e uma lista que vai enchendo é a diferença entre
/// parecer travado e parecer rápido.
#[tauri::command]
async fn scan_start(
    app: AppHandle,
    state: State<'_, AppState>,
    interface: String,
    target_cidr: String,
    // "none" salta a fase de portas: varredura de presença em segundos, sem
    // tocar em serviço nenhum. Comentário normal, não doc comment: Rust só
    // aceita atributos (cfg, allow, deny...) em parâmetro de função.
    port_profile: Option<String>,
) -> Result<(), String> {
    if state.scanning.swap(true, Ordering::SeqCst) {
        return Err("Já existe uma varredura em andamento.".into());
    }
    state.cancel.store(false, Ordering::SeqCst);

    let db_path = state.db_path.clone();
    let scanning = state.scanning.clone();
    let cancel = state.cancel.clone();
    let profile = match port_profile.as_deref() {
        Some("none") => PortProfile::None,
        Some("extended") => PortProfile::Extended,
        _ => PortProfile::Common,
    };
    let exclusions = {
        let conn = state.conn()?;
        load_exclusions(&conn).map_err(|e| e.to_string())?
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ScanEvent>(512);

    // Ponte: canal do núcleo → emit do Tauri.
    //
    // Um canal por tipo de evento, para o frontend poder escutar só o que
    // interessa em cada tela.
    let app_ev = app.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let channel = match &ev {
                ScanEvent::Progress { .. } => "scan:progress",
                ScanEvent::Device { .. } => "scan:device",
                ScanEvent::Finished { .. } => "scan:finished",
                ScanEvent::Failed { .. } => "scan:failed",
            };
            let _ = app_ev.emit(channel, &ev);
        }
    });

    // A varredura roda em THREAD PRÓPRIA, com runtime de thread única e
    // conexão própria.
    //
    // Não dá para usar `tokio::spawn` aqui. Ele exige que o future seja
    // `Send`, e o de `scan::run` não é: `rusqlite::Connection` contém
    // `RefCell`, logo não é `Sync`, e a varredura mantém uma referência ao
    // banco viva por cima de vários `.await`. O compilador reclama com
    // `RefCell<InnerConnection> cannot be shared between threads safely`.
    //
    // Forçar `Send` exigiria mover toda a conexão para dentro de
    // `spawn_blocking` a cada consulta, o que picaria as transações do diff
    // em pedaços e destruiria a atomicidade que elas existem para garantir.
    //
    // Uma thread dedicada resolve melhor: a conexão nasce e morre nela, nunca
    // atravessa fronteira nenhuma, e o `Send` deixa de ser exigido. E é o
    // lugar certo para um trabalho que leva minuto e é dominado por espera de
    // rede — ele não deve competir com os comandos da interface no runtime
    // principal.
    // Clone para o caminho de erro: o original é movido para dentro da
    // closure da thread, e ainda precisamos liberar a trava caso a própria
    // criação da thread falhe.
    let scanning_on_spawn_error = state.scanning.clone();

    std::thread::Builder::new()
        .name("sentinel-scan".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = app.emit(
                        "scan:failed",
                        serde_json::json!({ "error": format!("runtime: {e}") }),
                    );
                    scanning.store(false, Ordering::SeqCst);
                    return;
                }
            };

            let result = rt.block_on(async {
                let mut conn = store::open(&db_path)?;
                let cfg = ScanConfig {
                    interface,
                    target_cidr,
                    kind: "full".into(),
                    port_profile: profile,
                    exclusions,
                };
                scan::run(&mut conn, cfg, tx, cancel).await?;
                store::purge(&conn)?;
                Ok::<_, anyhow::Error>(())
            });

            if let Err(e) = result {
                let _ = app.emit(
                    "scan:failed",
                    serde_json::json!({ "error": e.to_string() }),
                );
            }
            // Sempre libera a trava, inclusive em erro. Sem isto um erro
            // deixa o botão travado em "Parar" até reiniciar o aplicativo.
            scanning.store(false, Ordering::SeqCst);
        })
        .map_err(|e| {
            scanning_on_spawn_error.store(false, Ordering::SeqCst);
            format!("não foi possível iniciar a thread de varredura: {e}")
        })?;

    Ok(())
}

#[tauri::command]
fn scan_cancel(state: State<'_, AppState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
fn scan_is_running(state: State<'_, AppState>) -> bool {
    state.scanning.load(Ordering::SeqCst)
}

#[tauri::command]
fn devices_list(state: State<'_, AppState>) -> Result<Vec<DeviceRow>, String> {
    let conn = state.conn()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, label, ip, mac, kind, vendor, os_guess, identity_confidence,
                    last_seen, miss_count, open_ports, finding_count, worst_severity_rank
               FROM v_device_summary
              ORDER BY worst_severity_rank IS NULL, worst_severity_rank, ip",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |r| {
            Ok(DeviceRow {
                id: r.get(0)?,
                label: r.get(1)?,
                ip: r.get(2)?,
                mac: r.get(3)?,
                kind: r.get(4)?,
                vendor: r.get(5)?,
                os_guess: r.get(6)?,
                identity_confidence: r.get(7)?,
                last_seen: r.get(8)?,
                miss_count: r.get(9)?,
                open_ports: r.get(10)?,
                finding_count: r.get(11)?,
                worst_severity_rank: r.get(12)?,
            })
        })
        .map_err(|e| e.to_string())?;

    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

#[tauri::command]
fn changes_list(state: State<'_, AppState>, include_acknowledged: bool) -> Result<Vec<ChangeRow>, String> {
    let conn = state.conn()?;
    let sql = format!(
        "SELECT c.id, c.device_id, a.value, d.label, c.type, c.severity,
                c.before, c.after, c.detected_at, c.acknowledged_at
           FROM change_event c
           JOIN device d ON d.id = c.device_id
           LEFT JOIN device_address a
             ON a.device_id = c.device_id AND a.kind='ip' AND a.is_current=1
          {}
          ORDER BY c.detected_at DESC
          LIMIT 200",
        if include_acknowledged { "" } else { "WHERE c.acknowledged_at IS NULL" }
    );

    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(ChangeRow {
                id: r.get(0)?,
                device_id: r.get(1)?,
                device_ip: r.get(2)?,
                device_label: r.get(3)?,
                change_type: r.get(4)?,
                severity: r.get(5)?,
                before: r.get(6)?,
                after: r.get(7)?,
                detected_at: r.get(8)?,
                acknowledged: r.get::<_, Option<i64>>(9)?.is_some(),
            })
        })
        .map_err(|e| e.to_string())?;

    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

#[tauri::command]
fn change_ack(state: State<'_, AppState>, id: i64) -> Result<(), String> {
    let conn = state.conn()?;
    conn.execute(
        "UPDATE change_event SET acknowledged_at = unixepoch(), acknowledged_by = ?2 WHERE id = ?1",
        rusqlite::params![id, actor()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Renomear ou reclassificar um dispositivo.
///
/// Marca `label_pinned` e `kind_source='manual'`: a partir daqui nenhuma
/// heurística sobrescreve. Decisão humana é definitiva.
#[tauri::command]
fn device_update(
    state: State<'_, AppState>,
    id: String,
    label: Option<String>,
    kind: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    let conn = state.conn()?;
    conn.execute(
        "UPDATE device
            SET label        = COALESCE(?2, label),
                label_pinned = CASE WHEN ?2 IS NOT NULL THEN 1 ELSE label_pinned END,
                kind         = COALESCE(?3, kind),
                kind_source  = CASE WHEN ?3 IS NOT NULL THEN 'manual' ELSE kind_source END,
                notes        = COALESCE(?4, notes),
                updated_at   = unixepoch()
          WHERE id = ?1",
        rusqlite::params![id, label, kind, notes],
    )
    .map_err(|e| e.to_string())?;

    audit(&conn, "device.update", &id);
    Ok(())
}

/// Concede consentimento para teste de credencial padrão num dispositivo.
///
/// Sem linha em `credential_consent`, o motor nem avalia as regras CRED-*.
/// O diálogo que coleta isto precisa explicar o risco de bloqueio de conta:
/// derrubar o administrador do domínio no meio da tarde não é jeito de
/// estrear a ferramenta.
#[tauri::command]
fn credential_consent_grant(
    state: State<'_, AppState>,
    device_id: String,
    note: Option<String>,
    valid_days: Option<i64>,
) -> Result<(), String> {
    let conn = state.conn()?;
    let expires = valid_days.map(|d| sentinel_core::model::now() + d * 86_400);

    conn.execute(
        "INSERT INTO credential_consent (device_id, granted_at, granted_by, expires_at, note)
         VALUES (?1, unixepoch(), ?2, ?3, ?4)
         ON CONFLICT (device_id) DO UPDATE
            SET granted_at = unixepoch(), granted_by = ?2, expires_at = ?3, note = ?4",
        rusqlite::params![device_id, actor(), expires, note],
    )
    .map_err(|e| e.to_string())?;

    audit(&conn, "consent.grant", &device_id);
    Ok(())
}

#[tauri::command]
fn credential_consent_revoke(state: State<'_, AppState>, device_id: String) -> Result<(), String> {
    let conn = state.conn()?;
    conn.execute(
        "DELETE FROM credential_consent WHERE device_id = ?1",
        rusqlite::params![device_id],
    )
    .map_err(|e| e.to_string())?;
    audit(&conn, "consent.revoke", &device_id);
    Ok(())
}

#[tauri::command]
fn exclusions_list(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let conn = state.conn()?;
    load_exclusions(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
fn exclusion_add(state: State<'_, AppState>, target: String, reason: Option<String>) -> Result<(), String> {
    if !iface::is_valid_target(&target) {
        return Err(format!("'{target}' não é um IP nem uma faixa CIDR válida."));
    }

    let conn = state.conn()?;
    conn.execute(
        "INSERT OR IGNORE INTO scan_exclusion (target, reason, created_at)
         VALUES (?1, ?2, unixepoch())",
        rusqlite::params![target, reason],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}


/// Catálogo de regras, carregado uma vez na inicialização.
///
/// O texto de explicação e correção vive no rules.toml, em Rust. O frontend
/// recebe uma cópia e usa para montar a tela de Achados. Duplicar esse texto
/// no JavaScript seria garantia de os dois ficarem diferentes com o tempo.
#[tauri::command]
fn rules_catalog() -> Vec<RuleInfo> {
    sentinel_core::rules::catalog()
        .rule
        .iter()
        .map(|r| RuleInfo {
            id: r.id.clone(),
            title: r.title.clone(),
            category: r.category.clone(),
            severity: r.base_severity.clone(),
            confidence: r.confidence.clone(),
            why: r.why.trim().to_string(),
            fix: r.fix.trim().to_string(),
            enabled: r.enabled,
            requires_consent: r.requires_explicit_consent,
        })
        .collect()
}

/// Tudo de um dispositivo: endereços, serviços abertos e achados.
///
/// Consulta separada da lista porque a lista não pode carregar isso: seriam
/// três consultas por linha, e com 250 dispositivos a tela levaria segundos
/// para abrir.
#[tauri::command]
fn device_detail(state: State<'_, AppState>, id: String) -> Result<DeviceDetail, String> {
    let conn = state.conn()?;

    let (label, kind, vendor, os_guess, confidence, hostname, first_seen, last_seen, notes) = conn
        .query_row(
            "SELECT label, kind, vendor, os_guess, identity_confidence, hostname,
                    first_seen, last_seen, notes
               FROM device WHERE id = ?1",
            rusqlite::params![id],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT kind, value, is_current FROM device_address
              WHERE device_id = ?1 ORDER BY is_current DESC, last_seen DESC",
        )
        .map_err(|e| e.to_string())?;
    let addresses = stmt
        .query_map(rusqlite::params![&id], |r| {
            Ok(AddressInfo {
                kind: r.get(0)?,
                value: r.get(1)?,
                is_current: r.get::<_, i64>(2)? == 1,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .collect();

    let mut stmt = conn
        .prepare(
            "SELECT protocol, port, service_name, banner FROM device_service
              WHERE device_id = ?1 AND closed_at IS NULL ORDER BY port",
        )
        .map_err(|e| e.to_string())?;
    let services = stmt
        .query_map(rusqlite::params![&id], |r| {
            Ok(ServiceInfo {
                protocol: r.get(0)?,
                port: r.get(1)?,
                service_name: r.get(2)?,
                banner: r.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .collect();

    // A view v_open_finding já filtra resolvido, aceito e suprimido.
    let mut stmt = conn
        .prepare(
            "SELECT id, rule_id, scope, severity_effective, confidence, evidence,
                    first_seen, accepted_at
               FROM v_open_finding WHERE device_id = ?1",
        )
        .map_err(|e| e.to_string())?;
    let findings = stmt
        .query_map(rusqlite::params![&id], |r| {
            Ok(FindingInfo {
                id: r.get(0)?,
                device_id: id.clone(),
                device_ip: None,
                rule_id: r.get(1)?,
                scope: r.get(2)?,
                severity: r.get(3)?,
                confidence: r.get(4)?,
                evidence: r.get(5)?,
                first_seen: r.get(6)?,
                accepted: r.get::<_, Option<i64>>(7)?.is_some(),
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .collect();

    Ok(DeviceDetail {
        id,
        label,
        kind,
        vendor,
        os_guess,
        hostname,
        identity_confidence: confidence,
        first_seen,
        last_seen,
        notes,
        addresses,
        services,
        findings,
    })
}

/// Todos os achados abertos, com o IP do dispositivo afetado.
///
/// O agrupamento por regra acontece no frontend, porque é decisão de
/// apresentação: a mesma lista serve para agrupar por regra ou por dispositivo.
#[tauri::command]
fn findings_list(state: State<'_, AppState>) -> Result<Vec<FindingInfo>, String> {
    let conn = state.conn()?;
    let mut stmt = conn
        .prepare(
            "SELECT f.id, f.device_id, a.value, f.rule_id, f.scope,
                    f.severity_effective, f.confidence, f.evidence, f.first_seen, f.accepted_at
               FROM v_open_finding f
               LEFT JOIN device_address a
                 ON a.device_id = f.device_id AND a.kind='ip' AND a.is_current=1
              ORDER BY CASE f.severity_effective
                         WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                         WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map([], |r| {
            Ok(FindingInfo {
                id: r.get(0)?,
                device_id: r.get(1)?,
                device_ip: r.get(2)?,
                rule_id: r.get(3)?,
                scope: r.get(4)?,
                severity: r.get(5)?,
                confidence: r.get(6)?,
                evidence: r.get(7)?,
                first_seen: r.get(8)?,
                accepted: r.get::<_, Option<i64>>(9)?.is_some(),
            })
        })
        .map_err(|e| e.to_string())?;

    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}

/// Aceitar um risco, com justificativa registrada.
///
/// Sem este mecanismo a lista de achados tem os mesmos quinze itens para
/// sempre e as pessoas param de olhar.
#[tauri::command]
fn finding_accept(
    state: State<'_, AppState>,
    id: i64,
    reason: String,
    valid_days: Option<i64>,
) -> Result<(), String> {
    let conn = state.conn()?;
    let until = valid_days.map(|d| sentinel_core::model::now() + d * 86_400);
    conn.execute(
        "UPDATE finding SET accepted_at = unixepoch(), accepted_by = ?2,
                            accepted_reason = ?3, accepted_until = ?4
          WHERE id = ?1",
        rusqlite::params![id, actor(), reason, until],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Auxiliares
// ---------------------------------------------------------------------------

fn load_exclusions(conn: &rusqlite::Connection) -> anyhow::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT target FROM scan_exclusion")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let list: Vec<String> = rows.filter_map(Result::ok).collect();
    Ok(list)
}

fn actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "desconhecido".into())
}

fn audit(conn: &rusqlite::Connection, action: &str, target: &str) {
    let _ = conn.execute(
        "INSERT INTO audit_log (at, actor, action, target_type, target_id)
         VALUES (unixepoch(), ?1, ?2, 'device', ?3)",
        rusqlite::params![actor(), action, target],
    );
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // RUST_LOG continua funcionando; "sentinel=debug" é só o padrão quando a
    // variável não está definida.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel=debug".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // O banco vai no diretório de dados do aplicativo, não junto do
            // executável: em Windows a pasta de Program Files não é gravável
            // pelo usuário comum.
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;

            app.manage(AppState {
                db_path: dir.join("sentinel.db"),
                scanning: Arc::new(AtomicBool::new(false)),
                cancel: Arc::new(AtomicBool::new(false)),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_capabilities,
            list_interfaces,
            scan_start,
            scan_cancel,
            scan_is_running,
            devices_list,
            changes_list,
            change_ack,
            device_update,
            credential_consent_grant,
            credential_consent_revoke,
            exclusions_list,
            exclusion_add,
            rules_catalog,
            device_detail,
            findings_list,
            finding_accept,
        ])
        .run(tauri::generate_context!())
        .expect("falha ao iniciar o SentinelStack");
}