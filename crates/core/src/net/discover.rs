//! Descoberta de hosts na rede local.
//!
//! Dois caminhos, escolhidos em tempo de execução conforme o privilégio:
//!
//! **Privilegiado** — ARP ativo com socket raw. Todo dispositivo na mesma VLAN
//! é obrigado a responder ARP, então isso encontra até quem bloqueia ping e
//! fecha todas as portas. Uma /24 leva poucos segundos.
//!
//! **Sem privilégio** — varredura TCP para forçar o sistema operacional a
//! resolver ARP por conta própria, seguida da leitura da tabela de vizinhança.
//! O truque: quando o SO tenta abrir uma conexão para um IP da rede local, ele
//! precisa do MAC e faz o ARP sozinho. Nós só lemos o cache depois. Não é tão
//! completo quanto o ARP direto (só encontra quem responde a alguma coisa),
//! mas funciona sem CAP_NET_RAW e sem Npcap.

use crate::model::{Mac, Method, Observation};
use anyhow::Result;
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Portas usadas só para provocar resolução ARP no modo sem privilégio.
/// Não é varredura de serviço: o que interessa é o SO fazer o ARP, e isso
/// acontece mesmo quando a conexão é recusada.
const NUDGE_PORTS: [u16; 4] = [80, 443, 22, 445];

// ---------------------------------------------------------------------------
// Caminho privilegiado: ARP ativo
// ---------------------------------------------------------------------------

/// Encontra a interface do pnet correspondente a um nome amigável.
///
/// Tenta, em ordem:
/// 1. casar pelo IPv4 — funciona em qualquer plataforma e é o caminho normal;
/// 2. casar pelo nome exato, para quem passar o caminho NPF direto;
/// 3. a primeira interface ativa com IPv4 e MAC, quando o nome vem vazio.
///
/// O passo 1 existe porque no Windows o nome do pnet é
/// `\Device\NPF_{GUID}`, e comparar com "Ethernet" nunca casa. Foi
/// exatamente esse o bug que fazia `arp_active` responder false mesmo com o
/// Npcap instalado e funcionando.
#[cfg(feature = "raw-socket")]
pub fn resolve_interface(name: &str) -> Option<pnet::datalink::NetworkInterface> {
    use pnet::datalink;

    let all = datalink::interfaces();

    // 1. Casar pelo IPv4. Caminho normal no Linux e no macOS.
    //
    // No Windows o pnet frequentemente devolve as interfaces com a lista de
    // IPs VAZIA — é uma limitação conhecida dele. Por isso este passo pode
    // falhar mesmo com tudo certo, e existem os passos seguintes.
    if let Some(want) = super::iface::ipv4_of(name) {
        if let Some(found) = all.iter().find(|i| {
            i.ips.iter().any(|n| match n.ip() {
                IpAddr::V4(v4) => v4 == want,
                _ => false,
            })
        }) {
            return Some(found.clone());
        }

        // 2. Casar pelo ÍNDICE do adaptador.
        //
        // O índice é o mesmo nos dois mundos: o if-addrs e o pnet leem da mesma
        // tabela do sistema. Isso resolve o Windows quando o pnet não trouxe
        // IP nenhum, que é justamente o caso que deixava tudo "sem ARP".
        if let Some(idx) = super::iface::index_of(name) {
            if let Some(found) = all.iter().find(|i| i.index == idx) {
                return Some(found.clone());
            }
        }
    }

    // 3. Casar pelo nome exato (para quem passar o caminho NPF direto).
    if let Some(found) = all.iter().find(|i| i.name == name) {
        return Some(found.clone());
    }

    // Chegou aqui: nada casou. Registra o que o pnet viu, para o diagnóstico
    // não depender de adivinhação na próxima vez.
    tracing::warn!(
        "interface '{}' não casou. if-addrs índice={:?} ipv4={:?}. pnet viu: {:?}",
        name,
        super::iface::index_of(name),
        super::iface::ipv4_of(name),
        all.iter()
            .map(|i| (i.name.clone(), i.index, i.ips.iter().map(|x| x.to_string()).collect::<Vec<_>>()))
            .collect::<Vec<_>>()
    );

    // 4. Nome vazio: primeira interface ativa com MAC. Quando nem isso resolve,
    // e ainda há uma única candidata plausível, usa ela — melhor tentar abrir o
    // canal e deixar o resultado real decidir do que declarar "sem ARP" cedo.
    let candidatas: Vec<_> = all
        .iter()
        .filter(|i| !i.is_loopback() && i.mac.is_some())
        .collect();
    if name.is_empty() {
        return candidatas.first().map(|i| (*i).clone());
    }
    if candidatas.len() == 1 {
        return Some(candidatas[0].clone());
    }

    None
}

/// Nomes internos das interfaces, como o pnet as vê, com seus IPs.
///
/// Só para diagnóstico. No Windows esses nomes são caminhos `\Device\NPF_{...}`
/// que não batem com o nome amigável, e ver os dois lado a lado é o que
/// explica por que a resolução por IP é necessária.
#[cfg(feature = "raw-socket")]
pub fn raw_interface_names() -> Vec<(String, Vec<String>)> {
    pnet::datalink::interfaces()
        .into_iter()
        .map(|i| (i.name, i.ips.iter().map(|n| n.to_string()).collect()))
        .collect()
}

#[cfg(not(feature = "raw-socket"))]
pub fn raw_interface_names() -> Vec<(String, Vec<String>)> {
    Vec::new()
}

#[cfg(feature = "raw-socket")]
pub fn arp_sweep(
    iface_name: &str,
    net: Ipv4Net,
    excluded: &dyn Fn(Ipv4Addr) -> bool,
    on_found: &mut dyn FnMut(Observation),
) -> Result<usize> {
    use anyhow::anyhow;
    use std::collections::HashMap;

    use pnet::datalink::{self, Channel, NetworkInterface};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::{MutablePacket, Packet};

    let iface: NetworkInterface = resolve_interface(iface_name)
        .ok_or_else(|| anyhow!("interface {iface_name} não encontrada"))?;

    let src_mac = iface
        .mac
        .ok_or_else(|| anyhow!("interface {iface_name} não tem MAC"))?;
    let src_ip = iface
        .ips
        .iter()
        .find_map(|n| match n.ip() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| anyhow!("interface {iface_name} não tem IPv4"))?;

    // O read_timeout é obrigatório, não otimização.
    //
    // Com a configuração padrão, `rx.next()` BLOQUEIA indefinidamente quando
    // nenhum pacote chega. Numa rede silenciosa (ou no loopback) o laço de
    // recepção nunca chega a checar o deadline e a varredura trava para
    // sempre. Com timeout curto, `next()` devolve Err periodicamente e o
    // deadline volta a funcionar.
    let cfg = datalink::Config {
        read_timeout: Some(Duration::from_millis(200)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&iface, cfg)? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("canal não suportado nesta interface")),
    };

    // Envio: uma rajada com intervalo entre pacotes.
    //
    // O intervalo não é pudor. Rajada sem espaçamento estoura buffer de switch
    // barato e, em rede com equipamento antigo, chega a derrubar a porta.
    for target in net.hosts() {
        if excluded(target) || target == src_ip {
            continue;
        }

        let mut eth_buf = [0u8; 42];
        let mut eth = MutableEthernetPacket::new(&mut eth_buf)
            .ok_or_else(|| anyhow!("buffer ethernet inválido"))?;
        eth.set_destination(pnet::datalink::MacAddr::broadcast());
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; 28];
        let mut arp =
            MutableArpPacket::new(&mut arp_buf).ok_or_else(|| anyhow!("buffer arp inválido"))?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(pnet::datalink::MacAddr::zero());
        arp.set_target_proto_addr(target);

        eth.set_payload(arp.packet_mut());
        tx.send_to(eth.packet(), None);

        std::thread::sleep(Duration::from_micros(800));
    }

    // Recepção: janela fixa depois do último envio.
    //
    // Equipamento embarcado antigo às vezes leva mais de um segundo para
    // responder, por isso a janela é generosa.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut seen: HashMap<Ipv4Addr, Mac> = HashMap::new();

    while std::time::Instant::now() < deadline {
        let frame = match rx.next() {
            Ok(f) => f,
            Err(_) => continue,
        };
        let Some(eth) = EthernetPacket::new(frame) else {
            continue;
        };
        if eth.get_ethertype() != EtherTypes::Arp {
            continue;
        }
        let Some(arp) = ArpPacket::new(eth.payload()) else {
            continue;
        };
        if arp.get_operation() != ArpOperations::Reply {
            continue;
        }

        let ip = arp.get_sender_proto_addr();
        let Some(mac) = Mac::parse(&arp.get_sender_hw_addr().to_string()) else {
            continue;
        };

        if seen.insert(ip, mac.clone()).is_none() {
            on_found(Observation {
                ip: Some(IpAddr::V4(ip)),
                mac: Some(mac),
                hostname: None,
                ttl: None,
                rtt_ms: None,
                method: Method::Arp,
                observed_at: crate::model::now(),
            });
        }
    }

    Ok(seen.len())
}

// ---------------------------------------------------------------------------
// Caminho sem privilégio
// ---------------------------------------------------------------------------

/// Provoca resolução ARP abrindo conexões TCP, depois lê a tabela do sistema.
pub async fn neighbor_sweep(
    net: Ipv4Net,
    excluded: &dyn Fn(Ipv4Addr) -> bool,
    concurrency: usize,
    mut on_progress: impl FnMut(usize, usize),
) -> Result<Vec<Observation>> {
    use tokio::sync::Semaphore;

    let targets: Vec<Ipv4Addr> = net.hosts().filter(|ip| !excluded(*ip)).collect();
    let total = targets.len();
    let sem = std::sync::Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(total);

    for ip in targets {
        let sem = sem.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            for port in NUDGE_PORTS {
                let addr = SocketAddr::new(IpAddr::V4(ip), port);
                // Recusa de conexão também serve: o ARP já aconteceu antes do
                // RST chegar. Só o timeout é inconclusivo.
                let r = tokio::time::timeout(
                    Duration::from_millis(700),
                    tokio::net::TcpStream::connect(addr),
                )
                .await;
                if matches!(r, Ok(Ok(_)) | Ok(Err(_))) {
                    return Some(ip);
                }
            }
            None
        }));
    }

    let mut done = 0usize;
    for t in tasks {
        let _ = t.await;
        done += 1;
        if done % 16 == 0 || done == total {
            on_progress(done, total);
        }
    }

    // Dar tempo para o cache assentar antes de ler.
    tokio::time::sleep(Duration::from_millis(300)).await;
    read_neighbor_table()
}

/// Lê a tabela ARP do sistema operacional.
///
/// Nunca falha: tabela indisponível significa "nenhum vizinho conhecido", não
/// "varredura falhou". Antes esta função propagava o erro do `Command`, e num
/// sistema sem `ip` nem `arp` no PATH (container enxuto, PATH restrito) a
/// varredura inteira morria com `No such file or directory`.
pub fn read_neighbor_table() -> Result<Vec<Observation>> {
    // No Linux, ler o arquivo é melhor que chamar comando: sempre existe,
    // não depende de PATH e não paga o custo de criar processo.
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        let found = parse_neighbor_table(&text);
        if !found.is_empty() {
            return Ok(found);
        }
    }

    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "windows") {
        &[("arp", &["-a"])]
    } else if cfg!(target_os = "linux") {
        &[("ip", &["neigh", "show"]), ("arp", &["-an"])]
    } else {
        &[("arp", &["-an"])]
    };

    for (bin, args) in attempts {
        match std::process::Command::new(bin).args(*args).output() {
            Ok(out) => {
                let found = parse_neighbor_table(&String::from_utf8_lossy(&out.stdout));
                if !found.is_empty() {
                    return Ok(found);
                }
            }
            Err(e) => {
                tracing::debug!("`{bin}` indisponível ({e}); tentando alternativa");
            }
        }
    }

    tracing::warn!(
        "não foi possível ler a tabela de vizinhança do sistema; \
         a descoberta sem privilégio vai encontrar menos dispositivos"
    );
    Ok(Vec::new())
}

/// Extrai pares IP/MAC de qualquer um dos três formatos.
///
/// Em vez de um parser por plataforma, procura em cada linha o primeiro token
/// que parece IPv4 e o primeiro que parece MAC. Os três formatos colocam os
/// dois na mesma linha, então isso cobre todos sem ramificação por SO.
fn parse_neighbor_table(text: &str) -> Vec<Observation> {
    let mut out = Vec::new();
    let ts = crate::model::now();

    for line in text.lines() {
        // Descarta entradas sem MAC resolvido.
        if line.contains("FAILED") || line.contains("INCOMPLETE") || line.contains("incomplete") {
            continue;
        }

        let mut ip: Option<Ipv4Addr> = None;
        let mut mac: Option<Mac> = None;

        for tok in line.split(|c: char| c.is_whitespace() || c == '(' || c == ')') {
            if ip.is_none() {
                if let Ok(parsed) = tok.parse::<Ipv4Addr>() {
                    ip = Some(parsed);
                    continue;
                }
            }
            if mac.is_none() && tok.matches(['-', ':']).count() == 5 {
                mac = Mac::parse(tok);
            }
        }

        if let (Some(ip), Some(mac)) = (ip, mac) {
            out.push(Observation {
                ip: Some(IpAddr::V4(ip)),
                mac: Some(mac),
                hostname: None,
                ttl: None,
                rtt_ms: None,
                method: Method::Neighbor,
                observed_at: ts,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parseia_ip_neigh_do_linux() {
        let s = "192.168.1.1 dev enp3s0 lladdr 48:8f:5a:12:0c:71 REACHABLE\n\
                 192.168.1.99 dev enp3s0  FAILED\n\
                 192.168.1.10 dev enp3s0 lladdr 00:1d:09:8b:3f:a2 STALE";
        let r = parse_neighbor_table(s);
        assert_eq!(r.len(), 2, "a entrada FAILED deve ser descartada");
        assert_eq!(r[0].mac.as_ref().unwrap().as_str(), "488F5A120C71");
    }

    #[test]
    fn parseia_arp_a_do_windows() {
        let s = "Interface: 192.168.1.5 --- 0xb\r\n\
                 Endereço IP  Endereço físico  Tipo\r\n\
                 192.168.1.1  48-8f-5a-12-0c-71  dinâmico";
        let r = parse_neighbor_table(s);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].mac.as_ref().unwrap().as_str(), "488F5A120C71");
    }

    #[test]
    fn parseia_arp_an_do_bsd() {
        let s = "? (192.168.1.1) at 48:8f:5a:12:0c:71 on en0 ifscope [ethernet]";
        let r = parse_neighbor_table(s);
        assert_eq!(r.len(), 1);
    }
}