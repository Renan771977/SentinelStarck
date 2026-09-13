//! Sugestão de comando de conexão por serviço.
//!
//! O app sabe qual serviço roda em cada porta; então, em vez de a pessoa
//! lembrar a sintaxe de cada cliente, montamos o comando certo. Isso fecha o
//! ciclo descobrir → agir sem o app virar um cliente de cada protocolo: ele
//! entrega o comando, e o terminal do sistema (ou o embutido) executa.
//!
//! A montagem fica AQUI, no núcleo, e não no frontend. Um lugar só, testável,
//! e o mesmo mapa alimenta tanto o botão "copiar" quanto os botões que abrem
//! uma sessão no terminal.

use serde::Serialize;
use std::net::IpAddr;

/// Onde os comandos vão rodar.
///
/// Detectado em tempo de compilação, mas passado como parâmetro para
/// `hints_for` a fim de os testes cobrirem os dois sistemas a partir de
/// qualquer máquina. No Kali há um arsenal que o Windows não tem —
/// smbclient, snmpwalk, nc — e faz diferença oferecer a ferramenta nativa em
/// vez de um comando que não existe naquele sistema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Unix,
}

impl Platform {
    /// A plataforma onde este binário está rodando.
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

/// Como o cliente se comporta, para a interface decidir o que oferecer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HintKind {
    /// Cliente interativo de terminal: SSH, MySQL, Redis. Pode abrir no
    /// terminal embutido.
    Shell,
    /// Abre no navegador: HTTP, HTTPS.
    Browser,
    /// Abre em aplicativo externo do sistema: RDP, VNC.
    External,
    /// Só há um comando de diagnóstico a copiar, sem cliente dedicado.
    Info,
}

/// Uma forma de conectar a um serviço.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectHint {
    /// Rótulo curto para o botão: "SSH", "MySQL", "Abrir no navegador".
    pub label: String,
    /// Comando pronto para copiar, com o IP e a porta já preenchidos.
    pub command: String,
    pub kind: HintKind,
    /// Aviso quando o protocolo é inseguro. A interface pinta de amarelo.
    pub warning: Option<String>,
}

/// Sugestões de conexão para uma porta.
///
/// A ordem importa: a primeira é a mais provável de ser o que a pessoa quer.
/// O banner refina o palpite quando disponível (uma porta 8080 pode ser HTTP
/// comum ou um proxy), mas a porta sozinha já basta na maioria dos casos.
pub fn hints_for(
    ip: IpAddr,
    port: u16,
    banner: Option<&str>,
    has_tls: bool,
    plat: Platform,
) -> Vec<ConnectHint> {
    let host = ip.to_string();
    let win = plat == Platform::Windows;
    let mut out = Vec::new();

    let shell = |label: &str, command: String, warning: Option<&str>| ConnectHint {
        label: label.into(),
        command,
        kind: HintKind::Shell,
        warning: warning.map(String::from),
    };

    match port {
        22 => out.push(shell("SSH", format!("ssh {host}"), None)),

        23 => out.push(shell(
            "Telnet",
            format!("telnet {host}"),
            Some("Telnet não é criptografado; a senha trafega em texto claro."),
        )),

        // Web. O esquema depende de TLS ter sido detectado, não da porta:
        // 8080 às vezes é HTTPS, 443 às vezes responde HTTP puro.
        80 | 8080 | 8000 | 8008 | 8888 => {
            let scheme = if has_tls { "https" } else { "http" };
            out.push(ConnectHint {
                label: "Abrir no navegador".into(),
                command: format!("{scheme}://{host}:{port}"),
                kind: HintKind::Browser,
                warning: (!has_tls).then(|| "HTTP sem TLS; credenciais trafegam em texto claro.".into()),
            });
        }
        443 | 8443 | 9443 => out.push(ConnectHint {
            label: "Abrir no navegador".into(),
            command: format!("https://{host}:{port}"),
            kind: HintKind::Browser,
            warning: None,
        }),

        3306 => out.push(shell("MySQL", format!("mysql -h {host} -u root -p"), None)),
        5432 => out.push(shell("PostgreSQL", format!("psql -h {host} -U postgres"), None)),
        1433 => out.push(shell("SQL Server", format!("sqlcmd -S {host} -U sa"), None)),
        27017 => out.push(shell("MongoDB", format!("mongosh mongodb://{host}:27017"), None)),
        6379 => out.push(shell("Redis", format!("redis-cli -h {host}"), None)),
        11211 => out.push(shell("Memcached", format!("telnet {host} 11211"), None)),
        9200 => out.push(ConnectHint {
            label: "Abrir no navegador".into(),
            command: format!("http://{host}:9200/_cluster/health?pretty"),
            kind: HintKind::Browser,
            warning: None,
        }),

        3389 => out.push(ConnectHint {
            label: "Área de trabalho remota".into(),
            command: if win {
                format!("mstsc /v:{host}")
            } else {
                format!("xfreerdp /v:{host}")
            },
            kind: HintKind::External,
            warning: None,
        }),
        5900 | 5901 => out.push(ConnectHint {
            label: "VNC".into(),
            command: format!("{host}:{port}"),
            kind: HintKind::External,
            warning: Some("VNC costuma ter criptografia fraca; use por VPN.".into()),
        }),

        21 => out.push(shell(
            "FTP",
            format!("ftp {host}"),
            Some("FTP não é criptografado; prefira SFTP."),
        )),
        445 => {
            // smbclient é do Linux; no Windows o equivalente nativo é net view.
            // No Kali dá para ir além e sugerir enumeração completa.
            if win {
                out.push(shell("SMB", format!("net view \\\\{host}"), None));
            } else {
                out.push(shell("SMB", format!("smbclient -L //{host} -N"), None));
                out.push(shell("Enumerar SMB", format!("enum4linux -a {host}"), None));
            }
        }
        161 => out.push(shell("SNMP", format!("snmpwalk -v2c -c public {host}"), None)),
        389 => out.push(shell("LDAP", format!("ldapsearch -x -H ldap://{host}"), None)),
        25 | 587 => out.push(shell("SMTP", format!("openssl s_client -connect {host}:{port} -starttls smtp"), None)),

        _ => {}
    }

    // O banner pode revelar que uma porta incomum é HTTP. Só acrescenta se
    // ainda não há sugestão de navegador.
    if let Some(b) = banner {
        let looks_http = b.starts_with("HTTP/") || b.to_ascii_lowercase().contains("server:");
        let has_browser = out.iter().any(|h| h.kind == HintKind::Browser);
        if looks_http && !has_browser {
            let scheme = if has_tls { "https" } else { "http" };
            out.push(ConnectHint {
                label: "Abrir no navegador".into(),
                command: format!("{scheme}://{host}:{port}"),
                kind: HintKind::Browser,
                warning: None,
            });
        }
    }

    // Teste de porta: comando certo por sistema. É o penúltimo recurso quando
    // não há cliente dedicado.
    if out.is_empty() {
        let (label, command) = if win {
            ("Testar porta", format!("Test-NetConnection {host} -Port {port}"))
        } else {
            // nc -zv é o teste rápido universal no Unix.
            ("Testar porta", format!("nc -zv {host} {port}"))
        };
        out.push(ConnectHint {
            label: label.into(),
            command,
            kind: HintKind::Info,
            warning: None,
        });
    }

    // No Unix (Kali), oferece sempre a varredura detalhada de serviço com
    // nmap: identificação de versão e scripts padrão. É a ferramenta que o
    // analista de rede espera ter à mão, e não existe no Windows por padrão.
    if !win {
        out.push(ConnectHint {
            label: "Nmap (versão + scripts)".into(),
            command: format!("nmap -sV -sC -p {port} {host}"),
            kind: HintKind::Info,
            warning: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "192.168.1.10".parse().unwrap()
    }
    const W: Platform = Platform::Windows;
    const U: Platform = Platform::Unix;

    #[test]
    fn ssh_monta_comando_certo() {
        // SSH é igual nos dois sistemas.
        for plat in [W, U] {
            let h = hints_for(ip(), 22, None, false, plat);
            assert_eq!(h[0].command, "ssh 192.168.1.10");
        }
    }

    #[test]
    fn telnet_avisa_texto_claro() {
        let h = hints_for(ip(), 23, None, false, W);
        assert!(h[0].warning.is_some());
    }

    #[test]
    fn web_usa_https_quando_ha_tls() {
        assert!(hints_for(ip(), 8080, None, false, W)[0].command.starts_with("http://"));
        assert!(hints_for(ip(), 8080, None, true, W)[0].command.starts_with("https://"));
    }

    #[test]
    fn mysql_inclui_host_e_usuario() {
        let h = hints_for(ip(), 3306, None, false, U);
        assert_eq!(h[0].command, "mysql -h 192.168.1.10 -u root -p");
    }

    #[test]
    fn banner_http_em_porta_incomum_oferece_navegador() {
        let h = hints_for(ip(), 7070, Some("HTTP/1.1 200 OK"), false, W);
        assert!(h.iter().any(|x| x.kind == HintKind::Browser));
    }

    #[test]
    fn porta_desconhecida_no_windows_usa_test_netconnection() {
        let h = hints_for(ip(), 51234, None, false, W);
        assert!(h.iter().any(|x| x.command.contains("Test-NetConnection")));
        assert!(!h.iter().any(|x| x.command.contains("nmap")), "nmap não é padrão no Windows");
    }

    #[test]
    fn porta_desconhecida_no_unix_usa_nc_e_oferece_nmap() {
        let h = hints_for(ip(), 51234, None, false, U);
        assert!(h.iter().any(|x| x.command.starts_with("nc -zv")));
        assert!(h.iter().any(|x| x.command.contains("nmap -sV")), "Kali tem nmap");
    }

    /// A frente principal: SMB e RDP têm comando diferente por sistema.
    #[test]
    fn smb_difere_entre_windows_e_unix() {
        let w = hints_for(ip(), 445, None, false, W);
        assert!(w[0].command.contains("net view"), "Windows usa net view");

        let u = hints_for(ip(), 445, None, false, U);
        assert!(u.iter().any(|x| x.command.contains("smbclient")), "Kali usa smbclient");
        assert!(u.iter().any(|x| x.command.contains("enum4linux")), "Kali oferece enum4linux");
    }

    #[test]
    fn rdp_usa_mstsc_no_windows_e_xfreerdp_no_unix() {
        assert!(hints_for(ip(), 3389, None, false, W)[0].command.contains("mstsc"));
        assert!(hints_for(ip(), 3389, None, false, U)[0].command.contains("xfreerdp"));
    }

    #[test]
    fn redis_e_mongo_tem_cliente_proprio() {
        assert!(hints_for(ip(), 6379, None, false, U)[0].command.contains("redis-cli"));
        assert!(hints_for(ip(), 27017, None, false, U)[0].command.contains("mongosh"));
    }
}