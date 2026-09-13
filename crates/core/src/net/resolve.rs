//! Resolução de nome.
//!
//! Só DNS reverso por enquanto. mDNS e NetBIOS entram junto com a escuta
//! passiva, porque compartilham a mesma infraestrutura de socket.

use std::net::IpAddr;
use std::time::Duration;

/// Faz DNS reverso, tolerando ausência de resposta.
///
/// A maioria das redes de PME não tem PTR configurado para host interno, então
/// o esperado é que isso falhe na maior parte das vezes. Não é erro.
pub async fn reverse_dns(ip: IpAddr, timeout: Duration) -> Option<String> {
    use hickory_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio_from_system_conf().ok()?;
    let lookup = tokio::time::timeout(timeout, resolver.reverse_lookup(ip))
        .await
        .ok()?
        .ok()?;

    lookup.iter().next().map(|n| {
        let s = n.to_string();
        s.trim_end_matches('.').to_string()
    })
}
