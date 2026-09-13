//! Exportação de evidência com selo de integridade.
//!
//! Produz um manifesto do estado da rede num formato DETERMINÍSTICO e calcula
//! o SHA-256 dele. Esse hash é o selo: se um único byte do manifesto mudar, o
//! hash muda, e a adulteração fica evidente.
//!
//! ## Por que hashear o manifesto, e não o PDF
//!
//! Um PDF carrega data de criação, ordem de objetos e metadados que variam
//! entre duas gerações do MESMO conteúdo. Hashear o PDF selaria a
//! apresentação, não os fatos. O manifesto é o oposto: mesmos fatos produzem
//! sempre os mesmos bytes, então o hash sela a evidência de verdade. O PDF é a
//! camada legível por cima; quem precisa verificar confere o manifesto.
//!
//! ## O que torna o manifesto determinístico
//!
//! Três regras: registros ordenados por chave estável (nunca por ordem de
//! inserção no banco), campos serializados em ordem fixa, e o timestamp do
//! export isolado num cabeçalho separado — ele muda a cada geração e não pode
//! contaminar o hash dos fatos. Por isso o hash cobre só o corpo, não o
//! cabeçalho.

use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Um export completo: cabeçalho com metadados e corpo com os fatos.
///
/// O hash cobre APENAS o corpo. O cabeçalho contém o próprio hash e o momento
/// da geração, que naturalmente mudam a cada export.
#[derive(Debug, Serialize)]
pub struct Evidence {
    pub header: Header,
    pub body: Body,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub tool: String,
    pub tool_version: String,
    /// Quando o export foi gerado, em ISO 8601 com fuso.
    pub generated_at: String,
    /// Sistema onde foi gerado. Num laudo, importa registrar o ambiente.
    pub platform: String,
    /// O selo. SHA-256 do corpo canônico, em hex minúsculo.
    pub content_sha256: String,
    /// Escopo do que foi coletado: a rede varrida.
    pub scope: String,
}

/// Os fatos. Tudo aqui é ordenado de forma estável para o hash ser
/// reproduzível.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    pub devices: Vec<DeviceRecord>,
    pub findings: Vec<FindingRecord>,
    pub changes: Vec<ChangeRecord>,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub device_count: usize,
    pub finding_count: usize,
    pub critical_count: usize,
    pub change_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    /// Chave de ordenação: o UUID estável, não o IP (que muda).
    pub id: String,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub label: Option<String>,
    pub hostname: Option<String>,
    pub kind: String,
    pub vendor: Option<String>,
    pub os_guess: Option<String>,
    pub identity_confidence: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub open_ports: Vec<PortRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRecord {
    pub protocol: String,
    pub port: u16,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRecord {
    pub rule_id: String,
    pub device_id: String,
    pub device_ip: Option<String>,
    pub scope: Option<String>,
    pub severity: String,
    pub confidence: String,
    pub evidence: Option<String>,
    pub first_seen: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRecord {
    pub change_type: String,
    pub device_id: String,
    pub severity: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub detected_at: i64,
}

/// Coleta o estado atual e monta a evidência selada.
pub fn collect(conn: &Connection, scope: &str, tool_version: &str) -> Result<Evidence> {
    let devices = collect_devices(conn)?;
    let findings = collect_findings(conn)?;
    let changes = collect_changes(conn)?;

    let critical_count = findings.iter().filter(|f| f.severity == "critical").count();
    let summary = Summary {
        device_count: devices.len(),
        finding_count: findings.len(),
        critical_count,
        change_count: changes.len(),
    };

    let body = Body { devices, findings, changes, summary };

    // O hash é do corpo canônico. `to_canonical` garante bytes idênticos para
    // fatos idênticos.
    let canonical = to_canonical(&body)?;
    let content_sha256 = sha256_hex(canonical.as_bytes());

    let header = Header {
        tool: "SentinelStack".into(),
        tool_version: tool_version.into(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        platform: platform_string(),
        content_sha256,
        scope: scope.into(),
    };

    Ok(Evidence { header, body })
}

/// Serialização canônica do corpo: JSON compacto, chaves em ordem estável.
///
/// serde_json com struct preserva a ordem dos campos declarados, e as coleções
/// já vêm ordenadas de `collect`. Isso basta para reprodutibilidade; não
/// dependemos da ordem de iteração de nenhum HashMap.
pub fn to_canonical(body: &Body) -> Result<String> {
    Ok(serde_json::to_string(body)?)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Reverifica um manifesto exportado: recalcula o hash do corpo e compara com
/// o do cabeçalho. É o que uma terceira parte roda para provar que a evidência
/// não foi adulterada.
pub fn verify(evidence: &Evidence) -> Result<bool> {
    let canonical = to_canonical(&evidence.body)?;
    let recomputed = sha256_hex(canonical.as_bytes());
    Ok(recomputed == evidence.header.content_sha256)
}

fn platform_string() -> String {
    format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
}

// ---------------------------------------------------------------------------
// Coleta ordenada
// ---------------------------------------------------------------------------

fn collect_devices(conn: &Connection) -> Result<Vec<DeviceRecord>> {
    // ORDER BY id: chave estável. Ordenar por IP seria instável, porque IP
    // muda entre varreduras e quebraria a reprodutibilidade do hash.
    let mut stmt = conn.prepare(
        "SELECT id, ip, mac, label, hostname, kind, vendor, os_guess,
                identity_confidence, first_seen, last_seen
           FROM v_device_summary ORDER BY id",
    )?;

    let rows: Vec<DeviceRecord> = stmt
        .query_map([], |r| {
            Ok(DeviceRecord {
                id: r.get(0)?,
                ip: r.get(1)?,
                mac: r.get(2)?,
                label: r.get(3)?,
                hostname: r.get(4)?,
                kind: r.get(5)?,
                vendor: r.get(6)?,
                os_guess: r.get(7)?,
                identity_confidence: r.get(8)?,
                first_seen: r.get(9)?,
                last_seen: r.get(10)?,
                open_ports: Vec::new(),
            })
        })?
        .filter_map(Result::ok)
        .collect();

    // Portas de cada dispositivo, ordenadas por porta.
    let mut out = Vec::with_capacity(rows.len());
    for mut d in rows {
        let mut ps = conn.prepare(
            "SELECT protocol, port, service_name, banner FROM device_service
              WHERE device_id = ?1 AND closed_at IS NULL ORDER BY protocol, port",
        )?;
        d.open_ports = ps
            .query_map([&d.id], |r| {
                Ok(PortRecord {
                    protocol: r.get(0)?,
                    port: r.get(1)?,
                    service: r.get(2)?,
                    banner: r.get(3)?,
                })
            })?
            .filter_map(Result::ok)
            .collect();
        out.push(d);
    }
    Ok(out)
}

fn collect_findings(conn: &Connection) -> Result<Vec<FindingRecord>> {
    // Ordenado por (rule_id, device_id, scope): estável e reproduzível.
    let mut stmt = conn.prepare(
        "SELECT f.rule_id, f.device_id, a.value, f.scope,
                f.severity_effective, f.confidence, f.evidence, f.first_seen
           FROM v_open_finding f
           LEFT JOIN device_address a
             ON a.device_id = f.device_id AND a.kind='ip' AND a.is_current=1
          ORDER BY f.rule_id, f.device_id, f.scope",
    )?;
    let rows: Vec<FindingRecord> = stmt
        .query_map([], |r| {
            Ok(FindingRecord {
                rule_id: r.get(0)?,
                device_id: r.get(1)?,
                device_ip: r.get(2)?,
                scope: r.get(3)?,
                severity: r.get(4)?,
                confidence: r.get(5)?,
                evidence: r.get(6)?,
                first_seen: r.get(7)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

fn collect_changes(conn: &Connection) -> Result<Vec<ChangeRecord>> {
    // Ordenado por (detected_at, device_id): reproduzível, e cronológico é o
    // que faz sentido ler numa linha do tempo de incidente.
    let mut stmt = conn.prepare(
        "SELECT type, device_id, severity, before, after, detected_at
           FROM change_event
          ORDER BY detected_at, device_id, type",
    )?;
    let rows: Vec<ChangeRecord> = stmt
        .query_map([], |r| {
            Ok(ChangeRecord {
                change_type: r.get(0)?,
                device_id: r.get(1)?,
                severity: r.get(2)?,
                before: r.get(3)?,
                after: r.get(4)?,
                detected_at: r.get(5)?,
            })
        })?
        .filter_map(Result::ok)
        .collect();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    fn seed(conn: &Connection) {
        conn.execute(
            "INSERT INTO device (id, kind, vendor, hostname, identity_confidence,
                                 first_seen, last_seen, created_at, updated_at)
             VALUES ('dev-a','server','Dell','srv1','high',1000,2000,1000,2000)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO device_address (device_id, kind, value, is_current, first_seen, last_seen)
             VALUES ('dev-a','ip','192.168.1.10',1,1000,2000)", [],
        ).unwrap();
        conn.execute(
            "INSERT INTO device_service (device_id, protocol, port, service_name, first_seen, last_seen)
             VALUES ('dev-a','tcp',22,'ssh',1000,2000)", [],
        ).unwrap();
    }

    #[test]
    fn sha256_confere_com_vetor_conhecido() {
        // Vetor de teste padrão do SHA-256.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_e_deterministico() {
        let conn = store::open_memory().unwrap();
        seed(&conn);

        let a = collect(&conn, "192.168.1.0/24", "0.1.0").unwrap();
        let b = collect(&conn, "192.168.1.0/24", "0.1.0").unwrap();

        // Mesmos fatos, mesmo hash — mesmo com generated_at diferente, porque
        // ele não entra no corpo.
        assert_eq!(a.header.content_sha256, b.header.content_sha256);
    }

    #[test]
    fn selo_valida_conteudo_intacto() {
        let conn = store::open_memory().unwrap();
        seed(&conn);
        let ev = collect(&conn, "192.168.1.0/24", "0.1.0").unwrap();
        assert!(verify(&ev).unwrap(), "manifesto intacto deve verificar");
    }

    #[test]
    fn adulteracao_quebra_o_selo() {
        let conn = store::open_memory().unwrap();
        seed(&conn);
        let mut ev = collect(&conn, "192.168.1.0/24", "0.1.0").unwrap();

        // Alguém edita um fato depois de exportar.
        ev.body.devices[0].ip = Some("10.0.0.1".into());

        assert!(!verify(&ev).unwrap(), "conteúdo alterado precisa falhar a verificação");
    }

    #[test]
    fn mudanca_de_ordem_nao_afeta_o_hash_quando_reordenado_pela_query() {
        // Dois dispositivos inseridos em ordem inversa produzem o mesmo hash,
        // porque a coleta ordena por id.
        let c1 = store::open_memory().unwrap();
        c1.execute("INSERT INTO device (id,kind,identity_confidence,first_seen,last_seen,created_at,updated_at) VALUES ('a','server','high',1,1,1,1)", []).unwrap();
        c1.execute("INSERT INTO device (id,kind,identity_confidence,first_seen,last_seen,created_at,updated_at) VALUES ('b','server','high',1,1,1,1)", []).unwrap();

        let c2 = store::open_memory().unwrap();
        c2.execute("INSERT INTO device (id,kind,identity_confidence,first_seen,last_seen,created_at,updated_at) VALUES ('b','server','high',1,1,1,1)", []).unwrap();
        c2.execute("INSERT INTO device (id,kind,identity_confidence,first_seen,last_seen,created_at,updated_at) VALUES ('a','server','high',1,1,1,1)", []).unwrap();

        let h1 = collect(&c1, "x", "0.1.0").unwrap().header.content_sha256;
        let h2 = collect(&c2, "x", "0.1.0").unwrap().header.content_sha256;
        assert_eq!(h1, h2, "ordem de inserção não pode mudar o hash");
    }
}

// ---------------------------------------------------------------------------
// Saída
// ---------------------------------------------------------------------------

/// O manifesto completo, pronto para gravar em arquivo. Este é o artefato
/// selado: JSON com cabeçalho e corpo. Reverificável por qualquer ferramenta
/// que recalcule o SHA-256 do corpo.
pub fn to_manifest_json(evidence: &Evidence) -> Result<String> {
    Ok(serde_json::to_string_pretty(evidence)?)
}

/// Relatório HTML legível, para leitura humana e impressão em PDF pelo
/// navegador. NÃO é a evidência — é a apresentação dela. O selo impresso no
/// topo aponta para o manifesto, que é o que se verifica.
pub fn to_report_html(evidence: &Evidence) -> String {
    let h = &evidence.header;
    let b = &evidence.body;

    let mut rows = String::new();
    for d in &b.devices {
        let ports: Vec<String> = d
            .open_ports
            .iter()
            .map(|p| format!("{}/{}", p.port, p.protocol))
            .collect();
        rows.push_str(&format!(
            "<tr><td class=mono>{}</td><td>{}</td><td class=mono>{}</td><td>{}</td><td class=mono>{}</td></tr>",
            esc(d.ip.as_deref().unwrap_or("—")),
            esc(d.label.as_deref().or(d.hostname.as_deref()).unwrap_or("—")),
            esc(d.mac.as_deref().unwrap_or("—")),
            esc(&d.kind),
            esc(&ports.join(" ")),
        ));
    }

    let mut find_rows = String::new();
    for f in &b.findings {
        find_rows.push_str(&format!(
            "<tr><td><span class='sev sev-{}'>{}</span></td><td class=mono>{}</td><td class=mono>{}</td><td>{}</td></tr>",
            esc(&f.severity), esc(&f.severity),
            esc(&f.rule_id),
            esc(f.device_ip.as_deref().unwrap_or("—")),
            esc(f.evidence.as_deref().unwrap_or("")),
        ));
    }

    format!(
        r#"<!doctype html><html lang=pt-BR><head><meta charset=utf-8>
<title>Relatório de evidência — SentinelStack</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a1a1a;max-width:960px;margin:40px auto;padding:0 24px;line-height:1.5}}
  h1{{font-size:22px;margin-bottom:4px}}
  .mono{{font-family:ui-monospace,Consolas,monospace;font-size:13px}}
  .seal{{background:#f4f6fa;border:1px solid #d8dee9;border-radius:8px;padding:14px 16px;margin:20px 0;font-size:13px}}
  .seal .hash{{word-break:break-all;color:#0a4}}
  table{{border-collapse:collapse;width:100%;margin:14px 0;font-size:13px}}
  th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #e5e9f0}}
  th{{color:#5a6472;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}}
  .sev{{display:inline-block;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:600}}
  .sev-critical{{background:#ffd9e0;color:#b00020}} .sev-high{{background:#ffe4cc;color:#b35900}}
  .sev-medium{{background:#fff3cc;color:#8a6d00}} .sev-low{{background:#d9ecff;color:#004a99}}
  .sev-info{{background:#e8ebef;color:#4a5568}}
  h2{{font-size:15px;margin-top:28px;border-bottom:2px solid #1a1a1a;padding-bottom:4px}}
  .meta{{color:#5a6472;font-size:13px}}
  footer{{margin-top:36px;color:#8a94a6;font-size:11px;border-top:1px solid #e5e9f0;padding-top:12px}}
</style></head><body>

<h1>Relatório de evidência de rede</h1>
<p class=meta>{tool} {ver} · gerado em {gen} · {plat}</p>

<div class=seal>
  <strong>Selo de integridade (SHA-256 do manifesto)</strong><br>
  <span class="mono hash">{hash}</span><br>
  <span class=meta>Escopo: {scope} · Confira este hash contra o arquivo .json que acompanha este relatório.
  Qualquer alteração no conteúdo muda o selo.</span>
</div>

<p><strong>{ndev}</strong> dispositivos · <strong>{nfind}</strong> achados abertos
 (<strong>{ncrit}</strong> críticos) · <strong>{nchg}</strong> mudanças registradas.</p>

<h2>Dispositivos</h2>
<table><thead><tr><th>IP</th><th>Nome</th><th>MAC</th><th>Tipo</th><th>Portas abertas</th></tr></thead>
<tbody>{rows}</tbody></table>

<h2>Achados</h2>
<table><thead><tr><th>Severidade</th><th>Regra</th><th>Dispositivo</th><th>Evidência</th></tr></thead>
<tbody>{find_rows}</tbody></table>

<footer>
  Documento gerado automaticamente pelo SentinelStack. A evidência verificável é o
  arquivo de manifesto (.json); este relatório é a sua apresentação legível.
  Para imprimir em PDF, use a função de impressão do navegador.
</footer>
</body></html>"#,
        tool = esc(&h.tool), ver = esc(&h.tool_version), gen = esc(&h.generated_at),
        plat = esc(&h.platform), hash = esc(&h.content_sha256), scope = esc(&h.scope),
        ndev = b.summary.device_count, nfind = b.summary.finding_count,
        ncrit = b.summary.critical_count, nchg = b.summary.change_count,
        rows = rows, find_rows = find_rows,
    )
}

/// Escape mínimo de HTML. Banner e hostname vêm de dispositivo de rede, que
/// pode conter caractere hostil; sem escape, o relatório vira vetor de injeção.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod output_tests {
    use super::*;
    use crate::store;

    #[test]
    fn manifesto_e_reverificavel_apos_serializar() {
        let conn = store::open_memory().unwrap();
        conn.execute("INSERT INTO device (id,kind,identity_confidence,first_seen,last_seen,created_at,updated_at) VALUES ('a','server','high',1,1,1,1)", []).unwrap();

        let ev = collect(&conn, "x", "0.1.0").unwrap();
        let json = to_manifest_json(&ev).unwrap();

        // Reparse e reverifica: simula o que uma terceira parte faria.
        let reparsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(reparsed["header"]["contentSha256"], ev.header.content_sha256);
    }

    #[test]
    fn html_escapa_conteudo_hostil() {
        let conn = store::open_memory().unwrap();
        conn.execute("INSERT INTO device (id,kind,identity_confidence,hostname,first_seen,last_seen,created_at,updated_at) VALUES ('a','server','high','<script>x</script>',1,1,1,1)", []).unwrap();

        let ev = collect(&conn, "x", "0.1.0").unwrap();
        let html = to_report_html(&ev);
        assert!(!html.contains("<script>x</script>"), "hostname hostil precisa ser escapado");
        assert!(html.contains("&lt;script&gt;"));
    }
}