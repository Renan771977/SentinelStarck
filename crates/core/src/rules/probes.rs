//! Sondas para os matchers que não dão para expressar no TOML.
//!
//! Todas seguem a mesma disciplina: **confirmar a condição sem alterar nada**.
//! Nenhuma sonda aqui escreve, cria, apaga ou autentica. O que separa esta
//! ferramenta de um scanner de ataque é exatamente essa linha.
//!
//! São estas que produzem os achados de confiança `confirmed`, e é por isso
//! que valem o esforço: "porta 6379 aberta" é palpite, "o Redis respondeu
//! PONG sem senha" é fato.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Resultado de uma sonda: a condição existe, e a evidência que prova.
#[derive(Debug, Clone)]
pub struct ProbeHit {
    pub confirmed: bool,
    pub evidence: String,
}

async fn connect(ip: IpAddr, port: u16, t: Duration) -> Option<TcpStream> {
    tokio::time::timeout(t, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .ok()?
        .ok()
}

/// DB-001 — Redis sem autenticação.
///
/// `PING` é o comando mais inofensivo do protocolo: não lê nem escreve dado.
/// Com senha configurada, o servidor responde `-NOAUTH`; sem senha, `+PONG`.
/// A distinção é inequívoca, e é o que permite severidade crítica com
/// confiança confirmada.
pub async fn redis_noauth(ip: IpAddr, t: Duration) -> Option<ProbeHit> {
    let mut s = connect(ip, 6379, t).await?;
    s.write_all(b"*1\r\n$4\r\nPING\r\n").await.ok()?;

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(t, s.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    // Resposta -NOAUTH ou -WRONGPASS significa que há senha configurada, que é
    // o comportamento correto. Qualquer outra resposta é inconclusiva. Nos dois
    // casos não há achado.
    resp.starts_with("+PONG").then(|| ProbeHit {
        confirmed: true,
        evidence: "PING respondeu +PONG sem AUTH".into(),
    })
}

/// DB-004 — Memcached alcançável.
///
/// `version` é somente leitura e não expõe conteúdo em cache. Suficiente para
/// confirmar que o serviço responde a qualquer um na rede, que é o problema.
pub async fn memcached_reachable(ip: IpAddr, t: Duration) -> Option<ProbeHit> {
    let mut s = connect(ip, 11211, t).await?;
    s.write_all(b"version\r\n").await.ok()?;

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(t, s.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    resp.starts_with("VERSION").then(|| ProbeHit {
        confirmed: true,
        evidence: format!("respondeu: {}", resp.trim()),
    })
}

/// DB-003 — Elasticsearch sem autenticação.
///
/// `GET /` devolve nome do cluster e versão. Com segurança ativada, devolve
/// 401. Nenhum índice é lido.
pub async fn elastic_noauth(ip: IpAddr, t: Duration) -> Option<ProbeHit> {
    let mut s = connect(ip, 9200, t).await?;
    s.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .ok()?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(t, s.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.starts_with("HTTP/1.0 401") || resp.starts_with("HTTP/1.1 401") {
        return None; // Protegido.
    }
    resp.contains("\"cluster_name\"").then(|| ProbeHit {
        confirmed: true,
        evidence: "GET / devolveu informação do cluster sem credencial".into(),
    })
}

/// WIN-001 — SMBv1 habilitado.
///
/// Envia um NEGOTIATE PROTOCOL oferecendo apenas dialetos SMBv1. Se o servidor
/// aceita, ele suporta SMBv1. Isto é negociação de protocolo: acontece ANTES de
/// qualquer autenticação, então não gera evento de login nem risco de bloqueio
/// de conta.
pub async fn smb_v1_negotiated(ip: IpAddr, t: Duration) -> Option<ProbeHit> {
    // Pacote NEGOTIATE mínimo oferecendo "NT LM 0.12" e "SMB 2.???".
    // Um servidor só-SMBv2+ responde com erro ou fecha; um que aceita SMBv1
    // responde com o dialeto escolhido.
    const NEGOTIATE_SMB1: &[u8] = &[
        0x00, 0x00, 0x00, 0x54,                         // NetBIOS: tamanho
        0xFF, 0x53, 0x4D, 0x42,                         // "\xFFSMB"
        0x72,                                           // SMB_COM_NEGOTIATE
        0x00, 0x00, 0x00, 0x00,                         // status
        0x18, 0x53, 0xC8,                               // flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x2F, 0x4B, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x31, 0x00,                               // ByteCount
        0x02, b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2', 0x00,
    ];

    let mut s = connect(ip, 445, t).await?;
    s.write_all(NEGOTIATE_SMB1).await.ok()?;

    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(t, s.read(&mut buf)).await.ok()?.ok()?;
    if n < 9 {
        return None;
    }

    // Resposta em SMBv1 começa com \xFFSMB. Servidor moderno com SMBv1
    // desativado responde em SMB2 (\xFESMB) ou derruba a conexão.
    let is_smb1 = buf[4..8] == [0xFF, 0x53, 0x4D, 0x42];
    let status_ok = buf[9..13] == [0x00, 0x00, 0x00, 0x00];

    (is_smb1 && status_ok).then(|| ProbeHit {
        confirmed: true,
        evidence: "servidor aceitou negociação em dialeto SMBv1 (NT LM 0.12)".into(),
    })
}

/// EOL-001 a EOL-004 — fim de suporte.
///
/// Fato de calendário, não correlação com CVE. Ver a nota no rules.toml sobre
/// por que banner de versão nunca vira CVE aqui: distribuições fazem backport
/// de correção sem mudar o número da versão, e uma ferramenta que erra isso
/// perde a confiança do cliente de uma vez.
pub fn eol_lookup(os_guess: &str, today_epoch: i64) -> Option<ProbeHit> {
    let eol = &super::catalog().eol;

    for (product, date) in eol {
        if !os_guess.to_ascii_lowercase().contains(&product.to_ascii_lowercase()) {
            continue;
        }
        let Some(d) = date.date else { continue };

        // Conversão aproximada para epoch: dias desde 1970.
        let days = days_from_civil(d.year as i64, d.month as i64, d.day as i64);
        let eol_epoch = days * 86_400;

        if today_epoch > eol_epoch {
            return Some(ProbeHit {
                confirmed: true,
                evidence: format!(
                    "{product} saiu de suporte em {:04}-{:02}-{:02}",
                    d.year, d.month, d.day
                ),
            });
        }
    }
    None
}

/// Dias desde 1970-01-01. Algoritmo de Howard Hinnant, exato e sem
/// dependência de crate de data.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------------------------------------------------------------------
// Despachante
// ---------------------------------------------------------------------------


/// Decide quais sondas rodar e executa as aplicáveis.
///
/// Só roda sonda cuja porta está aberta: nada de tentar Redis em host que não
/// tem 6379 escutando. Além de economizar tempo, isso evita conexão inútil no
/// log do cliente.
///
/// Retorna `(evidências, sondas_que_rodaram)`. A segunda parte alimenta o
/// `EvalCoverage` e é o que separa "não tem problema" de "não olhei": uma
/// sonda que falhou por timeout **não** entra no conjunto.
pub async fn run_for_host(
    ip: IpAddr,
    open_ports: &[u16],
    os_guess: Option<&str>,
    t: Duration,
) -> (HashMap<String, String>, HashSet<String>) {
    let mut hits = HashMap::new();
    let mut ran = HashSet::new();
    let open: HashSet<u16> = open_ports.iter().copied().collect();

    macro_rules! probe {
        ($name:literal, $port:expr, $call:expr) => {
            if open.contains(&$port) {
                ran.insert($name.to_string());
                if let Some(h) = $call.await {
                    hits.insert($name.to_string(), h.evidence);
                }
            }
        };
    }

    probe!("redis_noauth", 6379, redis_noauth(ip, t));
    probe!("memcached_reachable", 11211, memcached_reachable(ip, t));
    probe!("elastic_noauth", 9200, elastic_noauth(ip, t));
    probe!("smb_v1_negotiated", 445, smb_v1_negotiated(ip, t));

    // TLS em qualquer porta que costuma falar TLS. A inspeção alimenta cinco
    // regras de uma vez, então roda uma vez por porta e o resultado é
    // repartido entre elas no avaliador.
    for tls_port in [443u16, 465, 636, 993, 995, 8443, 9443, 5001] {
        if open.contains(&tls_port) {
            ran.insert("tls_inspect".to_string());
            if let Some(info) = crate::net::tls::inspect(ip, tls_port, t).await {
                let now = crate::model::now();
                let scope = format!("tcp/{tls_port}");
                if info.expired(now) {
                    hits.insert(format!("cert_expired:{scope}"),
                        format!("certificado vencido em {tls_port}/tcp"));
                }
                if let Some(secs) = info.seconds_until_expiry(now) {
                    if secs > 0 && secs < 30 * 86_400 {
                        hits.insert(format!("cert_expiring_soon:{scope}"),
                            format!("certificado vence em {} dias", secs / 86_400));
                    }
                }
                if info.legacy_protocol() {
                    hits.insert(format!("tls_legacy_version:{scope}"),
                        format!("{} aceito em {tls_port}/tcp", info.protocol));
                }
                if info.weak_key() {
                    hits.insert(format!("cert_weak_key:{scope}"),
                        format!("chave {} {} bits", info.key_type.clone().unwrap_or_default(),
                                info.key_bits.unwrap_or(0)));
                }
                if info.self_signed {
                    hits.insert(format!("cert_self_signed:{scope}"),
                        "certificado autoassinado".to_string());
                }
            }
        }
    }

    // eol_lookup não depende de porta: depende de conhecer o sistema.
    if let Some(os) = os_guess {
        ran.insert("eol_lookup".to_string());
        if let Some(h) = eol_lookup(os, crate::model::now()) {
            hits.insert("eol_lookup".to_string(), h.evidence);
        }
    }

    (hits, ran)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversao_de_data_confere() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(2024, 6, 30), 19904);
    }

    #[test]
    fn detecta_windows_server_2012_fora_de_suporte() {
        // 2026-09-12
        let hoje = days_from_civil(2026, 9, 12) * 86_400;
        let hit = eol_lookup("Windows Server 2012 R2", hoje);
        assert!(hit.is_some());
        assert!(hit.unwrap().evidence.contains("2023"));
    }

    #[test]
    fn windows_server_2016_ainda_suportado_em_2026() {
        let hoje = days_from_civil(2026, 9, 12) * 86_400;
        assert!(eol_lookup("Windows Server 2016", hoje).is_none(), "EOL em 2027-01-12");
    }

    /// Em setembro de 2026, o Windows 10 já está fora de suporte. Vai acender
    /// em muita máquina de PME brasileira, e é achado legítimo.
    #[test]
    fn windows_10_esta_fora_de_suporte_hoje() {
        let hoje = days_from_civil(2026, 9, 12) * 86_400;
        assert!(eol_lookup("Windows 10", hoje).is_some());
    }

    #[test]
    fn sistema_desconhecido_nao_gera_achado() {
        let hoje = days_from_civil(2026, 9, 12) * 86_400;
        assert!(eol_lookup("SistemaQualquer 1.0", hoje).is_none());
    }
}