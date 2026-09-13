//! Terminal embutido.
//!
//! Uma sessão de PTY por aba, cada uma com processo próprio. Usa
//! `portable-pty`, que abstrai o ConPTY do Windows e o `forkpty` do Unix — a
//! mesma biblioteca por trás do WezTerm.
//!
//! ## Por que não implementamos SSH
//!
//! Basta abrir o `ssh` do sistema dentro do PTY. O Windows 10 e 11 já trazem
//! o OpenSSH, e assim ganhamos de graça gerenciamento de chave, `known_hosts`,
//! agente e negociação com equipamento antigo. Escrever um cliente SSH em Rust
//! levaria semanas e seria pior em todos esses pontos.
//!
//! ## Por que o frontend não monta linha de comando
//!
//! Ele manda uma intenção estruturada (`{kind:"ssh", host:"192.168.1.2"}`) e é
//! aqui que o `argv` é construído, com cada argumento separado e sem shell no
//! meio. Isso elimina injeção de comando por construção, não por validação de
//! string. Se o frontend mandasse `"ssh 192.168.1.2; formatar disco"`, o host
//! inteiro chegaria como um único argumento e o `ssh` simplesmente falharia.
//!
//! ## O módulo é opcional de propósito
//!
//! Está atrás da feature `terminal`, ligada por padrão. Um terminal embutido é
//! execução de comando arbitrário: inofensivo num aplicativo local, onde o
//! usuário já tem shell na máquina, e perigoso no dia em que alguma versão
//! disso rodar dentro da rede de um cliente. Compilar sem a feature remove o
//! código do binário, em vez de depender de alguém lembrar de desabilitar.

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

/// O que abrir. Vem do frontend como JSON marcado por `kind`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SessionSpec {
    /// Shell local: PowerShell no Windows, `$SHELL` no Unix.
    Shell,
    Ssh {
        host: String,
        user: Option<String>,
        port: Option<u16>,
    },
    Telnet {
        host: String,
        port: Option<u16>,
    },
    /// Ping contínuo, a ferramenta mais usada em diagnóstico de rede.
    Ping { host: String },
    Traceroute { host: String },
}

impl SessionSpec {
    fn kind_str(&self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Ssh { .. } => "ssh",
            Self::Telnet { .. } => "telnet",
            Self::Ping { .. } => "ping",
            Self::Traceroute { .. } => "traceroute",
        }
    }

    fn target(&self) -> Option<&str> {
        match self {
            Self::Shell => None,
            Self::Ssh { host, .. }
            | Self::Telnet { host, .. }
            | Self::Ping { host }
            | Self::Traceroute { host } => Some(host),
        }
    }

    /// Constrói o comando. Cada argumento é um item separado do `argv`:
    /// nenhum shell interpreta a string, então não há injeção possível.
    fn build(&self) -> Result<CommandBuilder, String> {
        // Defesa em profundidade: o `argv` já protege, mas exigir IP válido
        // evita que um alvo digitado errado vire um processo pendurado
        // esperando resolução de nome.
        if let Some(host) = self.target() {
            if host.parse::<IpAddr>().is_err() {
                return Err(format!("'{host}' não é um endereço IP válido."));
            }
        }

        let windows = cfg!(target_os = "windows");

        let cmd = match self {
            Self::Shell => {
                if windows {
                    CommandBuilder::new("powershell.exe")
                } else {
                    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
                    CommandBuilder::new(shell)
                }
            }

            Self::Ssh { host, user, port } => {
                let mut c = CommandBuilder::new("ssh");
                if let Some(p) = port {
                    c.arg("-p");
                    c.arg(p.to_string());
                }
                // Sem -o StrictHostKeyChecking=no de propósito. Aceitar chave
                // desconhecida em silêncio anula a proteção contra
                // interceptação, e num produto de segurança isso é
                // contraditório. O usuário confirma a impressão digital na
                // primeira conexão, como deve ser.
                c.arg(match user {
                    Some(u) => format!("{u}@{host}"),
                    None => host.clone(),
                });
                c
            }

            Self::Telnet { host, port } => {
                let mut c = CommandBuilder::new("telnet");
                c.arg(host);
                if let Some(p) = port {
                    c.arg(p.to_string());
                }
                c
            }

            Self::Ping { host } => {
                let mut c = CommandBuilder::new("ping");
                // -t no Windows, -c 0 não existe: no Unix o ping já é contínuo.
                if windows {
                    c.arg("-t");
                }
                c.arg(host);
                c
            }

            Self::Traceroute { host } => {
                let mut c = if windows {
                    CommandBuilder::new("tracert")
                } else {
                    CommandBuilder::new("traceroute")
                };
                c.arg(host);
                c
            }
        };

        Ok(cmd)
    }
}

struct Session {
    /// Mantido vivo: descartar o master fecha o PTY e mata o processo.
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
}

#[derive(Default)]
pub struct PtyRegistry {
    sessions: Mutex<HashMap<String, Session>>,
}

impl PtyRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Abre uma sessão e começa a bombear a saída para o frontend.
pub fn open(
    app: &AppHandle,
    registry: &Arc<PtyRegistry>,
    spec: SessionSpec,
    rows: u16,
    cols: u16,
) -> Result<String, String> {
    let cmd = spec.build()?;
    let id = uuid::Uuid::new_v4().to_string();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: rows.max(4),
            cols: cols.max(20),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("não foi possível abrir o PTY: {e}"))?;

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| format!("não foi possível iniciar '{}': {e}", spec.kind_str()))?;

    // O slave precisa ser descartado aqui. Se ficar aberto do nosso lado, o
    // PTY nunca sinaliza fim de arquivo quando o processo termina, e a thread
    // de leitura fica pendurada para sempre.
    drop(pair.slave);

    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("leitor do PTY: {e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("escritor do PTY: {e}"))?;
    let killer = child.clone_killer();

    registry.sessions.lock().unwrap().insert(
        id.clone(),
        Session {
            master: pair.master,
            writer,
            killer,
        },
    );

    // Thread de leitura. Thread do sistema, não task async: a leitura do PTY é
    // bloqueante e não tem versão assíncrona portável.
    let app_out = app.clone();
    let sid = id.clone();
    std::thread::Builder::new()
        .name(format!("pty-read-{}", &id[..8]))
        .spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Base64 em vez de String::from_utf8_lossy.
                        //
                        // A saída do terminal quebra em pedaços arbitrários, e
                        // um caractere UTF-8 pode ficar partido entre duas
                        // leituras. Converter aqui transformaria acentos em
                        // caracteres de substituição. O xterm remonta os bytes
                        // corretamente do outro lado.
                        let data = base64_encode(&buf[..n]);
                        let _ = app_out.emit(
                            "pty:output",
                            serde_json::json!({ "id": sid, "data": data }),
                        );
                    }
                    Err(_) => break,
                }
            }
            let code = child.wait().ok().map(|s| s.exit_code()).unwrap_or(0);
            let _ = app_out.emit("pty:exit", serde_json::json!({ "id": sid, "code": code }));
        })
        .map_err(|e| format!("thread de leitura: {e}"))?;

    tracing::info!(
        session = %id, kind = spec.kind_str(), target = ?spec.target(),
        "sessão de terminal aberta"
    );

    Ok(id)
}

/// Escreve as teclas no PTY.
///
/// **Nunca registre este conteúdo em log.** Um terminal captura senha, e
/// gravar as teclas transformaria a trilha de auditoria num arquivo de
/// credenciais.
pub fn write(registry: &Arc<PtyRegistry>, id: &str, data: &str) -> Result<(), String> {
    let mut guard = registry.sessions.lock().unwrap();
    let s = guard.get_mut(id).ok_or("sessão não encontrada")?;
    s.writer
        .write_all(data.as_bytes())
        .map_err(|e| e.to_string())?;
    s.writer.flush().map_err(|e| e.to_string())
}

/// Propaga o tamanho da janela.
///
/// Sem isso, programa de tela cheia (vim, menu de configuração de switch)
/// desenha fora do lugar, porque acha que o terminal tem 80 colunas.
pub fn resize(registry: &Arc<PtyRegistry>, id: &str, rows: u16, cols: u16) -> Result<(), String> {
    let guard = registry.sessions.lock().unwrap();
    let s = guard.get(id).ok_or("sessão não encontrada")?;
    s.master
        .resize(PtySize {
            rows: rows.max(4),
            cols: cols.max(20),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())
}

pub fn close(registry: &Arc<PtyRegistry>, id: &str) {
    if let Some(mut s) = registry.sessions.lock().unwrap().remove(id) {
        // Matar antes de descartar: fechar só o master deixaria o processo
        // órfão em algumas plataformas.
        let _ = s.killer.kill();
    }
    tracing::info!(session = %id, "sessão de terminal encerrada");
}

pub fn close_all(registry: &Arc<PtyRegistry>) {
    let ids: Vec<String> = registry.sessions.lock().unwrap().keys().cloned().collect();
    for id in ids {
        close(registry, &id);
    }
}

/// Base64 padrão, sem dependência extra.
fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;

        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_confere_com_casos_conhecidos() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn base64_preserva_bytes_nao_utf8() {
        // Metade de um caractere UTF-8: é exatamente o que chega quando a
        // leitura do PTY corta no meio de um acento.
        assert_eq!(base64_encode(&[0xC3]), "ww==");
        assert_eq!(base64_encode(&[0xC3, 0xA7]), "w6c=");
    }

    /// Alvo que não é IP precisa ser recusado antes de virar processo.
    #[test]
    fn recusa_alvo_que_nao_e_ip() {
        let spec = SessionSpec::Ssh {
            host: "192.168.1.2; formatar".into(),
            user: None,
            port: None,
        };
        assert!(spec.build().is_err());

        let spec = SessionSpec::Ping { host: "lixo".into() };
        assert!(spec.build().is_err());
    }

    #[test]
    fn aceita_ip_valido() {
        let spec = SessionSpec::Ssh {
            host: "192.168.1.2".into(),
            user: Some("admin".into()),
            port: Some(2222),
        };
        assert!(spec.build().is_ok());
    }

    #[test]
    fn shell_nao_exige_alvo() {
        assert!(SessionSpec::Shell.build().is_ok());
        assert_eq!(SessionSpec::Shell.target(), None);
    }
}