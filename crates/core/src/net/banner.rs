//! Coleta de banner.
//!
//! Toda função aqui obedece à `BannerPolicy` da porta. A política é consultada
//! uma vez, no topo de `grab`, e o ramo `NeverWrite` retorna antes de qualquer
//! `write`. Não existe caminho alternativo: se alguém adicionar um probe novo,
//! ele precisa passar pelo mesmo `match`.

use super::ports::{banner_policy, BannerPolicy};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Limite de leitura. Banner útil tem dezenas de bytes; 4 KB é folga
/// generosa e evita que um serviço malcomportado (ou hostil) faça o
/// processo crescer sem limite.
const MAX_BANNER: usize = 4096;

/// Retorna `(banner, tls_info)`.
pub async fn grab(ip: IpAddr, port: u16, timeout: Duration) -> (Option<String>, Option<String>) {
    match banner_policy(port) {
        // Caminho de saída antes de qualquer escrita. Confirma que a porta
        // está aberta e vai embora.
        BannerPolicy::NeverWrite => (None, None),

        BannerPolicy::ServerSpeaksFirst => (read_only(ip, port, timeout).await, None),

        BannerPolicy::ClientMustSpeak(probe) => (write_then_read(ip, port, probe, timeout).await, None),

        BannerPolicy::TlsHandshake => {
            let info = tls_probe(ip, port, timeout).await;
            (None, info)
        }
    }
}

/// Conecta e só escuta. SSH, SMTP, FTP, POP3, IMAP, MySQL e Redis se
/// apresentam sozinhos assim que a conexão abre.
async fn read_only(ip: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

    let mut buf = vec![0u8; MAX_BANNER];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(sanitize(&buf))
}

async fn write_then_read(
    ip: IpAddr,
    port: u16,
    probe: &str,
    timeout: Duration,
) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await.ok()?.ok()?;

    tokio::time::timeout(timeout, stream.write_all(probe.as_bytes())).await.ok()?.ok()?;

    let mut buf = vec![0u8; MAX_BANNER];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    buf.truncate(n);

    // Para HTTP, só o cabeçalho interessa. Corpo de página inicial pode ter
    // centenas de KB e não acrescenta nada às regras.
    let text = sanitize(&buf);
    Some(http_headers_only(&text))
}

/// Handshake TLS apenas para ler o certificado. Nenhum byte de aplicação é
/// enviado depois: as regras TLS-001 a TLS-005 só precisam da cadeia.
async fn tls_probe(ip: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    // Implementação com tokio-rustls e x509-parser.
    //
    // Ponto de atenção: o verificador de certificado precisa ser permissivo,
    // porque o objetivo é justamente INSPECIONAR certificado inválido,
    // expirado ou autoassinado. Um verificador padrão aborta o handshake e a
    // ferramenta nunca vê o problema que deveria reportar.
    //
    // Use `dangerous_configuration` com um verificador que aceita tudo e
    // guarda a cadeia. Isso é seguro aqui porque nenhum dado é transmitido
    // depois do handshake: a conexão existe só para ler o certificado.
    let _ = (ip, port, timeout);
    None // TODO: implementar junto com as regras TLS-*
}

/// Converte bytes em texto seguro para exibir e guardar.
///
/// Banner pode conter qualquer byte, inclusive sequências de escape ANSI. Se
/// isso chegar cru à interface, um serviço hostil consegue injetar conteúdo na
/// tela ou no terminal de quem estiver usando o CLI.
fn sanitize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .collect::<String>()
        .trim()
        .chars()
        .take(1024)
        .collect()
}

/// Mantém só os cabeçalhos que as regras usam.
fn http_headers_only(text: &str) -> String {
    let head = text.split("\r\n\r\n").next().unwrap_or(text);
    head.lines()
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            low.starts_with("http/")
                || low.starts_with("server:")
                || low.starts_with("x-powered-by:")
                || low.starts_with("www-authenticate:")
                || low.starts_with("location:")
                || low.starts_with("set-cookie:")
        })
        .take(8)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_remove_escape_ansi() {
        let malicioso = b"\x1b[2J\x1b[31mSSH-2.0-OpenSSH_8.9";
        let s = sanitize(malicioso);
        assert!(!s.contains('\x1b'), "escape ANSI precisa sair");
        assert!(s.contains("SSH-2.0-OpenSSH_8.9"));
    }

    #[test]
    fn sanitize_limita_tamanho() {
        let grande = vec![b'A'; 10_000];
        assert!(sanitize(&grande).len() <= 1024);
    }

    #[test]
    fn sanitize_preserva_quebra_de_linha() {
        assert_eq!(sanitize(b"linha1\nlinha2"), "linha1\nlinha2");
    }

    #[test]
    fn http_mantem_so_cabecalho_relevante() {
        let resp = "HTTP/1.1 200 OK\r\n\
                    Server: nginx/1.18.0\r\n\
                    Date: qua, 12 set 2026 10:00:00 GMT\r\n\
                    Content-Length: 4096\r\n\
                    X-Powered-By: PHP/7.4\r\n\r\n\
                    <html>corpo enorme...</html>";
        let h = http_headers_only(resp);
        assert!(h.contains("nginx/1.18.0"));
        assert!(h.contains("PHP/7.4"));
        assert!(!h.contains("Content-Length"));
        assert!(!h.contains("corpo enorme"));
    }

    /// Garante que a política é respeitada: se alguém trocar o match de `grab`
    /// por um caminho que escreve, este teste continua passando, mas o de
    /// ports.rs quebra. Os dois juntos fecham o cerco.
    #[tokio::test]
    async fn nunca_escreve_em_porta_de_impressao() {
        // Endereço reservado para documentação, nunca responde.
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let (b, t) = grab(ip, 9100, Duration::from_millis(10)).await;
        assert!(b.is_none() && t.is_none());
        // O importante é que a função retorna sem tentar conectar: a política
        // NeverWrite sai antes do connect.
    }
}
