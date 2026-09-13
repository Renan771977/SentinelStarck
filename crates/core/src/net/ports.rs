//! Varredura de portas TCP e UDP.
//!
//! Três princípios, em ordem de importância:
//!
//! 1. **Nunca escrever em porta que interpreta bytes como comando.** A 9100 é
//!    JetDirect: qualquer byte enviado sai impresso em papel. A 515 (LPD) e a
//!    631 (IPP) têm o mesmo problema. A política de escrita é tipo, não
//!    convenção, para que seja impossível esquecer.
//!
//! 2. **Identificar o dispositivo antes de aprofundar.** Impressora e
//!    equipamento industrial travam com varredura agressiva. Por isso a
//!    descoberta e a resolução de fabricante acontecem ANTES desta fase: aqui
//!    já se sabe que 192.168.1.30 é uma HP e o tratamento muda.
//!
//! 3. **TCP connect, não SYN.** Mais lento e mais visível no log do cliente,
//!    mas não exige privilégio e não deixa conexão meio aberta em pilha TCP
//!    antiga, que é o que derruba equipamento embarcado.

use crate::model::DeviceKind;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Política de escrita
// ---------------------------------------------------------------------------

/// O que é seguro fazer depois de a conexão abrir.
///
/// Expressar isto como enum em vez de lista de exceções espalhada pelo código
/// significa que adicionar uma porta nova obriga a decidir a política dela.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerPolicy {
    /// O servidor fala primeiro. Só ler, nunca escrever.
    /// SSH, SMTP, FTP, POP3, IMAP, MySQL, Telnet.
    ServerSpeaksFirst,
    /// O cliente precisa falar primeiro para haver resposta. Envio de uma
    /// requisição mínima e bem formada.
    ClientMustSpeak(&'static str),
    /// Handshake TLS, depois leitura do certificado. Nenhum dado de aplicação.
    TlsHandshake,
    /// **Nunca escrever nada.** Abrir, confirmar que respondeu, fechar.
    /// Portas de impressão e de controle industrial.
    NeverWrite,
}

const HTTP_PROBE: &str = "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: SentinelStack\r\nConnection: close\r\n\r\n";

/// Política por porta. O padrão para porta desconhecida é `NeverWrite`:
/// silêncio é sempre seguro, e o custo de não obter banner é pequeno perto do
/// custo de travar um equipamento.
pub fn banner_policy(port: u16) -> BannerPolicy {
    use BannerPolicy::*;
    match port {
        // Portas de impressão e industriais: proibido escrever.
        9100..=9107 => NeverWrite, // JetDirect. Bytes viram papel.
        515 => NeverWrite,         // LPD
        631 => NeverWrite,         // IPP
        623 => NeverWrite,         // IPMI
        502 => NeverWrite,         // Modbus
        20000 => NeverWrite,       // DNP3
        44818 => NeverWrite,       // EtherNet/IP
        102 => NeverWrite,         // Siemens S7

        // Servidor se apresenta sozinho.
        21 | 22 | 23 | 25 | 110 | 143 | 3306 | 5432 | 6379 | 11211 | 27017 => ServerSpeaksFirst,

        // Precisa de requisição.
        80 | 8000 | 8008 | 8080 | 8081 | 8888 | 9200 => ClientMustSpeak(HTTP_PROBE),

        // TLS.
        443 | 465 | 636 | 993 | 995 | 5001 | 8443 | 9443 => TlsHandshake,

        _ => NeverWrite,
    }
}

// ---------------------------------------------------------------------------
// Perfis de porta
// ---------------------------------------------------------------------------

/// 147 portas que cobrem praticamente tudo que aparece em rede corporativa.
///
/// Varrer as 65.535 de 254 hosts é lento, ruidoso e quase sem retorno extra.
/// Esta lista existe para alimentar o catálogo de regras: cada porta aqui é
/// citada por pelo menos uma regra do rules.toml.
pub const PROFILE_COMMON: &[u16] = &[
    // Texto claro e acesso remoto
    21, 22, 23, 25, 69, 79, 110, 111, 113, 119, 143, 161, 162, 389, 512, 513, 514,
    // Web
    80, 81, 88, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9080, 9443,
    // Windows
    135, 137, 138, 139, 445, 1433, 3389, 5985, 5986, 47001,
    // Diretório e autenticação
    88, 464, 636, 3268, 3269, 749, 750,
    // Bancos e cache
    1521, 3050, 3306, 5000, 5432, 5984, 6379, 7000, 7001, 8086, 9042, 9160,
    9200, 9300, 11211, 27017, 27018, 28017, 5433, 1583,
    // Correio
    465, 587, 993, 995, 2525,
    // Arquivos e backup
    548, 873, 2049, 3260, 5001, 10000,
    // Impressão (só detecção, nunca escrita)
    515, 631, 9100, 9101, 9102,
    // Câmeras e mídia
    554, 1935, 5554, 7070, 8554, 37777,
    // Virtualização e orquestração
    902, 903, 2375, 2376, 2379, 2380, 6443, 8006, 10250, 10255,
    // Monitoramento e gerência
    199, 705, 1098, 1099, 4848, 5666, 5988, 5989, 6000, 6001, 7080,
    9090, 9100, 9091, 9093, 9094, 3000, 3001,
    // VPN e túnel
    500, 1194, 1701, 1723, 4500, 51820,
    // Industrial e embarcado
    102, 502, 623, 789, 2404, 4840, 20000, 44818,
    // Diversos frequentes
    1080, 1337, 2222, 3128, 4444, 5060, 5061, 5222, 5269, 5900, 5901, 5902,
    6667, 8291, 8728, 8729, 9999, 10001, 49152,
];

/// UDP é outra história: sem handshake, a ausência de resposta é ambígua, e
/// varredura ampla é lenta demais para ganho nenhum. Só o que importa.
pub const PROFILE_UDP: &[u16] = &[53, 67, 123, 137, 161, 500, 1900, 5353];

// ---------------------------------------------------------------------------
// Ritmo por tipo de dispositivo
// ---------------------------------------------------------------------------

/// Quantas conexões simultâneas abrir contra um host, e quanto esperar.
///
/// Limite POR HOST, não só global. Um semáforo global de 256 pode jogar 256
/// conexões simultâneas na mesma impressora, e ela cai. O limite global
/// controla o impacto na rede; o limite por host controla o impacto no
/// equipamento.
#[derive(Debug, Clone, Copy)]
pub struct HostPacing {
    pub concurrency: usize,
    pub timeout: Duration,
    pub delay_between: Duration,
}

pub fn pacing_for(kind: DeviceKind, vendor: Option<&str>) -> HostPacing {
    let v = vendor.unwrap_or("").to_ascii_lowercase();

    // Equipamento sabidamente frágil: um por vez, com folga.
    let fragile = matches!(kind, DeviceKind::Printer | DeviceKind::Camera | DeviceKind::Iot)
        || v.contains("hewlett")
        || v.contains("hp ")
        || v.contains("lexmark")
        || v.contains("zebra")
        || v.contains("siemens")
        || v.contains("rockwell")
        || v.contains("schneider");

    if fragile {
        return HostPacing {
            concurrency: 1,
            timeout: Duration::from_millis(1500),
            delay_between: Duration::from_millis(120),
        };
    }

    match kind {
        DeviceKind::Router | DeviceKind::Switch | DeviceKind::Firewall | DeviceKind::Ap => {
            // Equipamento de rede aguenta, mas travar o gateway derruba a
            // empresa inteira. Moderação.
            HostPacing {
                concurrency: 8,
                timeout: Duration::from_millis(1200),
                delay_between: Duration::from_millis(20),
            }
        }
        DeviceKind::Server | DeviceKind::Nas | DeviceKind::Workstation => HostPacing {
            concurrency: 32,
            timeout: Duration::from_millis(900),
            delay_between: Duration::ZERO,
        },
        // Desconhecido recebe tratamento conservador: pode ser qualquer coisa,
        // inclusive um CLP de linha de produção.
        _ => HostPacing {
            concurrency: 4,
            timeout: Duration::from_millis(1200),
            delay_between: Duration::from_millis(50),
        },
    }
}

// ---------------------------------------------------------------------------
// Varredura
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub protocol: &'static str,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub tls_info: Option<String>,
}

pub struct HostTarget {
    pub ip: IpAddr,
    pub kind: DeviceKind,
    pub vendor: Option<String>,
    /// Portas da linha de base, varridas sempre mesmo em perfil reduzido.
    pub baseline: HashSet<u16>,
}

/// Varre um host. Retorna só as portas abertas.
///
/// Não recebe `&Connection`: persistência é responsabilidade de quem chama.
/// Isso mantém a função testável sem banco e permite varrer em paralelo sem
/// contenção de lock no SQLite.
pub async fn scan_host(
    target: &HostTarget,
    ports: &[u16],
    global: Arc<Semaphore>,
    grab_banners: bool,
) -> Vec<OpenPort> {
    let pace = pacing_for(target.kind, target.vendor.as_deref());
    let host_sem = Arc::new(Semaphore::new(pace.concurrency));

    // Detecção precoce de host morto ou que não responde nada.
    //
    // Sem isso, um host offline consome 147 × timeout de espera. Com uma
    // sondagem inicial nas portas mais prováveis, um host silencioso custa
    // quatro timeouts em vez de cento e quarenta e sete.
    let probe_ports: Vec<u16> = [80, 443, 22, 445]
        .into_iter()
        .filter(|p| ports.contains(p))
        .collect();

    let mut open = Vec::new();
    let mut any_response = false;

    for p in &probe_ports {
        if connect(target.ip, *p, pace.timeout).await {
            any_response = true;
            open.push(*p);
        }
    }

    // Host que não respondeu em nenhuma porta comum ainda pode ter serviço em
    // porta incomum, mas a chance é baixa. Continua a varredura só se houver
    // linha de base definida, o que significa que alguém já viu algo lá.
    if !any_response && target.baseline.is_empty() {
        return Vec::new();
    }

    let remaining: Vec<u16> = ports
        .iter()
        .copied()
        .chain(target.baseline.iter().copied())
        .filter(|p| !probe_ports.contains(p))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let mut tasks = Vec::with_capacity(remaining.len());
    for port in remaining {
        let ip = target.ip;
        let g = global.clone();
        let h = host_sem.clone();
        let timeout = pace.timeout;
        let delay = pace.delay_between;

        tasks.push(tokio::spawn(async move {
            let _gp = g.acquire().await.ok()?;
            let _hp = h.acquire().await.ok()?;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if connect(ip, port, timeout).await {
                Some(port)
            } else {
                None
            }
        }));
    }

    for t in tasks {
        if let Ok(Some(p)) = t.await {
            open.push(p);
        }
    }

    open.sort_unstable();

    let mut result = Vec::with_capacity(open.len());
    for port in open {
        let (banner, tls_info) = if grab_banners {
            super::banner::grab(target.ip, port, pace.timeout).await
        } else {
            (None, None)
        };
        result.push(OpenPort {
            port,
            protocol: "tcp",
            service_name: service_name(port).map(String::from),
            banner,
            tls_info,
        });
    }

    result
}

async fn connect(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Nome convencional do serviço. Só rótulo: o que vale para as regras é o
/// banner, porque qualquer serviço pode estar em qualquer porta.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns",
        69 => "tftp", 80 => "http", 110 => "pop3", 111 => "rpcbind",
        135 => "msrpc", 137 => "netbios-ns", 139 => "netbios-ssn", 143 => "imap",
        161 => "snmp", 389 => "ldap", 443 => "https", 445 => "smb",
        502 => "modbus", 512 => "exec", 513 => "login", 514 => "shell",
        515 => "lpd", 554 => "rtsp", 587 => "smtp-submission", 623 => "ipmi",
        631 => "ipp", 636 => "ldaps", 873 => "rsync", 993 => "imaps",
        995 => "pop3s", 1433 => "mssql", 1521 => "oracle", 2049 => "nfs",
        2375 => "docker", 2376 => "docker-tls", 3306 => "mysql",
        3389 => "rdp", 5432 => "postgresql", 5900 => "vnc", 5985 => "winrm",
        5986 => "winrm-tls", 6379 => "redis", 6443 => "kubernetes",
        8006 => "proxmox", 8080 => "http-alt", 8291 => "winbox",
        9100 => "jetdirect", 9200 => "elasticsearch", 11211 => "memcached",
        27017 => "mongodb", 51820 => "wireguard",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// O teste mais importante deste arquivo.
    #[test]
    fn portas_de_impressao_nunca_recebem_escrita() {
        for p in [515u16, 631, 9100, 9101, 9102, 9107] {
            assert_eq!(
                banner_policy(p),
                BannerPolicy::NeverWrite,
                "porta {p} não pode receber escrita: bytes viram papel"
            );
        }
    }

    #[test]
    fn portas_industriais_nunca_recebem_escrita() {
        for p in [102u16, 502, 623, 20000, 44818] {
            assert_eq!(banner_policy(p), BannerPolicy::NeverWrite, "porta {p}");
        }
    }

    /// Porta desconhecida não pode cair num ramo permissivo por acidente.
    #[test]
    fn porta_desconhecida_e_silenciosa_por_padrao() {
        assert_eq!(banner_policy(31337), BannerPolicy::NeverWrite);
        assert_eq!(banner_policy(1), BannerPolicy::NeverWrite);
    }

    #[test]
    fn impressora_recebe_ritmo_conservador() {
        let p = pacing_for(DeviceKind::Printer, Some("HP Inc."));
        assert_eq!(p.concurrency, 1);
        assert!(p.delay_between > Duration::ZERO);
    }

    #[test]
    fn fabricante_frágil_vence_o_tipo() {
        // Classificado como servidor, mas o fabricante é industrial.
        let p = pacing_for(DeviceKind::Server, Some("Siemens AG"));
        assert_eq!(p.concurrency, 1);
    }

    #[test]
    fn desconhecido_e_conservador() {
        let p = pacing_for(DeviceKind::Unknown, None);
        assert!(p.concurrency <= 4, "pode ser um CLP de linha de produção");
    }

    #[test]
    fn perfil_comum_cobre_as_portas_do_catalogo() {
        // Portas citadas por regras críticas do rules.toml.
        for p in [23u16, 445, 3389, 6379, 27017, 9200, 11211, 161, 3306] {
            assert!(PROFILE_COMMON.contains(&p), "porta {p} está no catálogo mas não no perfil");
        }
    }
}
