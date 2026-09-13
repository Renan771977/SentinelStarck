# Changelog

## [0.1.0] — não lançado

Primeira fatia funcional: descobre, identifica, persiste, avalia e compara.

### Motor
- Descoberta ARP ativa com socket raw, e caminho alternativo sem privilégio
  que provoca resolução ARP por TCP e lê a tabela do sistema
- Identidade persistente de dispositivo: IP e MAC deixam de ser chave, e
  DHCP e MAC randomizado não duplicam mais o inventário
- Varredura de portas com política de escrita por porta e ritmo por tipo de
  dispositivo
- Catálogo de 48 regras em TOML, com severidade contextual
- Detecção de mudança em três níveis: dispositivo, serviço e achado
- Sondas ativas somente leitura para Redis, Memcached, Elasticsearch e SMBv1

### Interface
- Sete telas: visão geral, dispositivos, detalhe, achados, mudanças, mapa e
  configurações
- Dispositivos aparecem na lista um a um durante a varredura
- Modo limitado visível na interface quando falta privilégio

### Correções na primeira compilação
- `tokio` sem a feature `io-util`: `AsyncReadExt` e `AsyncWriteExt` não
  resolviam, quebrando a coleta de banner e todas as sondas
- Dois erros de empréstimo (E0597 e E0716) por devolver iterador que empresta
  um `Statement` local, em `load_baseline` e em `load_exclusions`
- **`Matcher` com `untagged` na ordem errada**: `{ custom = "..." }` era lido
  como um `Declarative` vazio, e um declarativo vazio casa com QUALQUER
  dispositivo. As 20 regras de sonda disparavam em todo host da rede.
  Corrigido com `Custom` primeiro e `deny_unknown_fields` no `Declarative`,
  mais dois testes de regressão
- Consentimento passou a ser o interruptor das regras `CRED-*`, em vez de
  ficar bloqueado pela flag `enabled = false`
- Canal de enlace sem `read_timeout`: `rx.next()` bloqueava para sempre em
  rede silenciosa e a varredura nunca terminava
- Porta 9200 citada pela regra DB-003 não estava no perfil de varredura
- `rusqlite` reexportado por `store` para o CLI não declarar versão própria

- `pnet` passou a ser dependência opcional, ativada pela feature
  `raw-socket`. Antes ela era obrigatória, e no Windows isso exigia o SDK do
  Npcap até só para rodar os testes (`LNK1181: cannot open input file
  'Packet.lib'`). Agora `--no-default-features` compila em qualquer máquina
- `sentinel-cli` e `sentinelstack-app` passaram a declarar
  `default-features = false` na dependência da core. Sem isso a unificação de
  features do Cargo reativava o `pnet` e `--no-default-features` não tinha
  efeito nenhum
- `app/src-tauri` declarado como workspace próprio, e `app/` excluído do
  workspace da raiz

### Fora desta versão
Sondas TLS, latência e jitter, escuta passiva, SNMP, relatório em PDF.
