//! Inspeção de certificado TLS.
//!
//! Faz o handshake, lê a cadeia de certificados e extrai o que as regras
//! TLS-001 a TLS-005 precisam. Nenhum dado de aplicação trafega: a conexão
//! existe só para pegar o certificado e fechar.
//!
//! ## Por que o verificador aceita tudo
//!
//! Parece contraditório num produto de segurança, mas o objetivo é
//! justamente INSPECIONAR certificado expirado, autoassinado e de CA
//! desconhecida. Um verificador normal aborta o handshake antes de a gente ver
//! o problema que deveria reportar. É seguro porque não enviamos nem recebemos
//! dado de aplicação: só lemos o que o servidor apresenta e encerramos.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// O que extraímos do certificado do servidor. Serializado para `tls_info` na
/// tabela `device_service`, e é a entrada das regras TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    /// Versão negociada: "TLS 1.3", "TLS 1.2", "TLS 1.0"...
    pub protocol: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    /// Nomes alternativos do certificado (dNSName, iPAddress).
    pub san: Vec<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// "RSA 2048", "EC P-256", "Ed25519"...
    pub key_type: Option<String>,
    pub key_bits: Option<u32>,
    /// Emissor igual ao sujeito: autoassinado.
    pub self_signed: bool,
    pub signature_algorithm: Option<String>,
}

impl TlsInfo {
    /// Segundos até o vencimento. Negativo se já venceu.
    pub fn seconds_until_expiry(&self, now: i64) -> Option<i64> {
        self.not_after.map(|exp| exp - now)
    }

    pub fn expired(&self, now: i64) -> bool {
        self.seconds_until_expiry(now).map(|s| s < 0).unwrap_or(false)
    }

    /// Regra TLS-003: protocolo obsoleto ainda aceito.
    pub fn legacy_protocol(&self) -> bool {
        self.protocol.contains("1.0") || self.protocol.contains("1.1")
    }

    /// Regra TLS-004: chave fraca. Só RSA tem esse problema no tamanho; curva
    /// elíptica de 256 bits é forte.
    pub fn weak_key(&self) -> bool {
        matches!((self.key_type.as_deref(), self.key_bits), (Some("RSA"), Some(bits)) if bits < 2048)
    }
}

/// Faz o handshake e devolve o certificado do servidor, ou None se a porta não
/// falar TLS. Nunca entra em pânico: porta que não é TLS simplesmente falha o
/// handshake, e isso não é erro.
#[cfg(feature = "tls-inspect")]
pub async fn inspect(ip: IpAddr, port: u16, timeout: Duration) -> Option<TlsInfo> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(accept_any::Verifier))
            .with_no_client_auth(),
    );

    let connector = TlsConnector::from(config);
    let addr = std::net::SocketAddr::new(ip, port);

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    // SNI com o IP. Muitos servidores respondem sem SNI, e o certificado que
    // interessa para inventário é o que o servidor apresenta por padrão.
    let server_name = ServerName::IpAddress(ip.into());

    let tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;

    let (_, conn) = tls.get_ref();

    let protocol = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLS 1.1",
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLS 1.0",
        _ => "TLS desconhecido",
    }
    .to_string();

    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;

    let mut info = parse_certificate(leaf.as_ref())?;
    info.protocol = protocol;
    Some(info)
}

#[cfg(not(feature = "tls-inspect"))]
pub async fn inspect(_ip: IpAddr, _port: u16, _timeout: Duration) -> Option<TlsInfo> {
    None
}

/// Extrai os campos do DER do certificado. Separado de `inspect` para poder
/// testar sem rede, com um certificado gerado em arquivo.
pub fn parse_certificate(der: &[u8]) -> Option<TlsInfo> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject = Some(cert.subject().to_string());
    let issuer = Some(cert.issuer().to_string());
    let self_signed = cert.subject() == cert.issuer();

    let not_before = Some(cert.validity().not_before.timestamp());
    let not_after = Some(cert.validity().not_after.timestamp());

    let signature_algorithm = cert
        .signature_algorithm
        .algorithm
        .to_id_string()
        .into();

    // Tipo e tamanho da chave pública.
    let (key_type, key_bits) = public_key_details(&cert);

    // SAN: dNSName e iPAddress.
    let mut san = Vec::new();
    if let Ok(Some(ext)) = cert.get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
        if let ParsedExtension::SubjectAlternativeName(names) = ext.parsed_extension() {
            for gn in &names.general_names {
                match gn {
                    GeneralName::DNSName(d) => san.push(d.to_string()),
                    GeneralName::IPAddress(bytes) => {
                        if let Some(ip) = ip_from_bytes(bytes) {
                            san.push(ip);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Some(TlsInfo {
        protocol: String::new(), // preenchido por `inspect`
        subject,
        issuer,
        san,
        not_before,
        not_after,
        key_type,
        key_bits,
        self_signed,
        signature_algorithm,
    })
}

fn public_key_details(cert: &x509_parser::certificate::X509Certificate) -> (Option<String>, Option<u32>) {
    use x509_parser::public_key::PublicKey;

    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => (Some("RSA".into()), Some((rsa.key_size()) as u32)),
        Ok(PublicKey::EC(ec)) => {
            // O tamanho do ponto revela a curva: 65 bytes = P-256, etc.
            let bits = match ec.data().len() {
                n if n >= 129 => 521,
                n if n >= 97 => 384,
                _ => 256,
            };
            (Some("EC".into()), Some(bits))
        }
        Ok(PublicKey::Unknown(_)) | Err(_) => (None, None),
        _ => (Some("outro".into()), None),
    }
}

fn ip_from_bytes(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()),
        16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(bytes);
            Some(std::net::Ipv6Addr::from(o).to_string())
        }
        _ => None,
    }
}

/// Verificador que aceita qualquer certificado.
///
/// Isolado num módulo para deixar explícito o quanto ele é permissivo. É
/// seguro porque a conexão só lê o certificado; nenhum dado de aplicação passa
/// por ela. Usar isto num cliente que troca dados de verdade seria uma falha
/// de segurança grave.
#[cfg(feature = "tls-inspect")]
mod accept_any {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct Verifier;

    impl ServerCertVerifier for Verifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            use SignatureScheme::*;
            vec![
                RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384,
                RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
                ED25519,
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analise_de_vencimento() {
        let info = TlsInfo {
            protocol: "TLS 1.2".into(),
            subject: None, issuer: None, san: vec![],
            not_before: Some(1_000),
            not_after: Some(2_000),
            key_type: Some("RSA".into()), key_bits: Some(2048),
            self_signed: false, signature_algorithm: None,
        };
        assert!(info.expired(3_000));
        assert!(!info.expired(1_500));
        assert_eq!(info.seconds_until_expiry(1_500), Some(500));
    }

    #[test]
    fn chave_rsa_fraca_e_detectada() {
        let mk = |bits| TlsInfo {
            protocol: "TLS 1.2".into(), subject: None, issuer: None, san: vec![],
            not_before: None, not_after: None,
            key_type: Some("RSA".into()), key_bits: Some(bits),
            self_signed: false, signature_algorithm: None,
        };
        assert!(mk(1024).weak_key());
        assert!(!mk(2048).weak_key());
        assert!(!mk(4096).weak_key());
    }

    #[test]
    fn curva_eliptica_de_256_nao_e_fraca() {
        let info = TlsInfo {
            protocol: "TLS 1.3".into(), subject: None, issuer: None, san: vec![],
            not_before: None, not_after: None,
            key_type: Some("EC".into()), key_bits: Some(256),
            self_signed: false, signature_algorithm: None,
        };
        assert!(!info.weak_key(), "EC 256 é forte, ao contrário de RSA 256");
    }

    #[test]
    fn protocolo_legado() {
        let mk = |p: &str| TlsInfo {
            protocol: p.into(), subject: None, issuer: None, san: vec![],
            not_before: None, not_after: None, key_type: None, key_bits: None,
            self_signed: false, signature_algorithm: None,
        };
        assert!(mk("TLS 1.0").legacy_protocol());
        assert!(mk("TLS 1.1").legacy_protocol());
        assert!(!mk("TLS 1.2").legacy_protocol());
        assert!(!mk("TLS 1.3").legacy_protocol());
    }

    #[test]
    fn ip_de_bytes() {
        assert_eq!(ip_from_bytes(&[192, 168, 1, 1]), Some("192.168.1.1".into()));
        assert_eq!(ip_from_bytes(&[1, 2, 3]), None);
    }

    /// Parsing de um certificado real, gerado no teste. Prova a cadeia inteira
    /// sem depender de rede.
    #[test]
    fn parseia_certificado_autoassinado_real() {
        // DER de um certificado autoassinado gerado com openssl, embutido em
        // base64 no arquivo de teste ao lado. Ver tls_fixtures.rs.
        let der = crate::net::tls_fixtures::SELF_SIGNED_DER;
        let info = parse_certificate(der).expect("deveria parsear");

        assert!(info.self_signed, "emissor igual ao sujeito");
        assert!(info.not_after.is_some());
        assert_eq!(info.key_type.as_deref(), Some("RSA"));
        assert!(info.subject.as_deref().unwrap().contains("sentinelstack.test"));
    }
}