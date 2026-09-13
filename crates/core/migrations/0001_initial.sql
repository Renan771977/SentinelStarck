-- ==========================================================================
--  SentinelStack — migração 0001, schema inicial
--
--  Aplicada por PRAGMA user_version. O runner em Rust verifica a versão
--  atual, aplica as migrações pendentes em ordem dentro de uma transação e
--  atualiza user_version ao final.
--
--  Pragmas de conexão (definidos no Rust, não aqui — journal_mode é
--  persistente e só precisa ser aplicado uma vez):
--    PRAGMA journal_mode = WAL;
--    PRAGMA foreign_keys = ON;      -- precisa ser ligado em TODA conexão
--    PRAGMA synchronous = NORMAL;   -- suficiente com WAL
--    PRAGMA busy_timeout = 5000;
--
--  CONVENÇÕES
--    Timestamps  INTEGER, epoch Unix em segundos, UTC. Formatação fica na
--                interface. Comparação e agregação ficam triviais.
--    Booleanos   INTEGER 0/1, com CHECK.
--    IDs de      TEXT contendo UUID v4, gerado no Rust. IDs de linha
--    entidade    auxiliar usam INTEGER autoincrement.
--    MAC         12 caracteres hex maiúsculos, sem separador. A
--                normalização acontece no Rust antes de qualquer insert ou
--                consulta. Formatação com dois-pontos é só de exibição.
--    IP          Texto na forma canônica. IPv4 sem zero à esquerda.
-- ==========================================================================


-- --------------------------------------------------------------------------
--  Configuração
-- --------------------------------------------------------------------------

CREATE TABLE setting (
    key         TEXT    NOT NULL PRIMARY KEY,
    value       TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

INSERT INTO setting (key, value, updated_at) VALUES
    ('scan.profile',            'safe',       unixepoch()),
    ('scan.port_profile',       'common',     unixepoch()),
    ('scan.max_concurrency',    '256',        unixepoch()),
    ('scan.tcp_timeout_ms',     '1000',       unixepoch()),
    ('device.miss_threshold',   '3',          unixepoch()),
    ('business_hours.start',    '08:00',      unixepoch()),
    ('business_hours.end',      '19:00',      unixepoch()),
    ('business_hours.weekdays', '1,2,3,4,5',  unixepoch()),
    ('retention.observation_days', '30',      unixepoch()),
    ('retention.probe_raw_hours',  '48',      unixepoch()),
    ('retention.probe_rollup_days','365',     unixepoch());


-- --------------------------------------------------------------------------
--  Faixas excluídas da varredura ativa
--
--  Aplicada na camada mais baixa do motor, nunca só na interface. Se a
--  exclusão for checada apenas na tela, um dia alguém chama a função direto
--  e a impressora do financeiro imprime trinta páginas em branco.
-- --------------------------------------------------------------------------

CREATE TABLE scan_exclusion (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL UNIQUE,   -- IP único ou CIDR
    reason      TEXT,
    created_at  INTEGER NOT NULL
) STRICT;


-- --------------------------------------------------------------------------
--  Servidores DHCP autorizados (base da regra HYG-002)
-- --------------------------------------------------------------------------

CREATE TABLE known_dhcp_server (
    mac         TEXT    NOT NULL PRIMARY KEY,
    ip          TEXT,
    note        TEXT,
    created_at  INTEGER NOT NULL
) STRICT;


-- --------------------------------------------------------------------------
--  Varreduras
--
--  `target_cidr`, `port_profile` e `status` juntos definem o ESCOPO COBERTO.
--  O diff só pode marcar dispositivo como ausente dentro do escopo que a
--  varredura realmente cobriu. Sem isso, uma varredura parcial ou cancelada
--  gera dezenas de "device_gone" falsos. É o bug mais comum nessa classe de
--  ferramenta.
-- --------------------------------------------------------------------------

CREATE TABLE scan (
    id              TEXT    NOT NULL PRIMARY KEY,
    kind            TEXT    NOT NULL CHECK (kind IN ('quick','full','passive','manual')),
    status          TEXT    NOT NULL CHECK (status IN ('running','completed','cancelled','failed')),

    interface_name  TEXT    NOT NULL,
    target_cidr     TEXT    NOT NULL,
    port_profile    TEXT    NOT NULL CHECK (port_profile IN ('none','common','extended','custom')),
    privileged      INTEGER NOT NULL DEFAULT 0 CHECK (privileged IN (0,1)),

    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,

    device_count    INTEGER NOT NULL DEFAULT 0,
    new_count       INTEGER NOT NULL DEFAULT 0,
    gone_count      INTEGER NOT NULL DEFAULT 0,
    error           TEXT
) STRICT;

CREATE INDEX idx_scan_started ON scan (started_at DESC);


-- --------------------------------------------------------------------------
--  Dispositivo — a entidade estável
--
--  O id NUNCA muda. IP e MAC vivem em device_address porque ambos são
--  voláteis: DHCP troca o IP, e o mesmo aparelho tem MAC diferente no cabo
--  e no Wi-Fi.
--
--  `label_pinned` e `kind_source` protegem decisão humana. Se o usuário
--  renomeou ou reclassificou, nenhuma heurística sobrescreve depois.
-- --------------------------------------------------------------------------

CREATE TABLE device (
    id                   TEXT    NOT NULL PRIMARY KEY,

    label                TEXT,
    label_pinned         INTEGER NOT NULL DEFAULT 0 CHECK (label_pinned IN (0,1)),

    kind                 TEXT    NOT NULL DEFAULT 'unknown'
                                 CHECK (kind IN ('router','switch','firewall','server','workstation',
                                                 'printer','camera','nas','ap','phone','iot','unknown')),
    kind_source          TEXT    NOT NULL DEFAULT 'auto' CHECK (kind_source IN ('auto','manual')),

    vendor               TEXT,
    hostname             TEXT,
    os_guess             TEXT,

    identity_confidence  TEXT    NOT NULL DEFAULT 'low'
                                 CHECK (identity_confidence IN ('high','medium','low')),

    first_seen           INTEGER NOT NULL,
    last_seen            INTEGER NOT NULL,
    last_scan_id         TEXT REFERENCES scan(id) ON DELETE SET NULL,

    -- Varreduras seguidas em que o dispositivo não apareceu, estando no
    -- escopo coberto. Só vira device_gone ao cruzar device.miss_threshold.
    -- Um único miss gerando alerta enche a tela de ruído: notebook dorme,
    -- resposta ARP se perde, máquina reinicia.
    miss_count           INTEGER NOT NULL DEFAULT 0,

    is_ignored           INTEGER NOT NULL DEFAULT 0 CHECK (is_ignored IN (0,1)),
    notes                TEXT,

    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_device_last_seen ON device (last_seen DESC);
CREATE INDEX idx_device_kind      ON device (kind);


-- --------------------------------------------------------------------------
--  Endereços — N por dispositivo
--
--  Índice único parcial: um IP pode ter pertencido a vários dispositivos ao
--  longo do tempo (DHCP reaproveita), mas só pode ser o endereço ATUAL de
--  um. O banco impede o erro em vez de confiar na aplicação.
-- --------------------------------------------------------------------------

CREATE TABLE device_address (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT    NOT NULL REFERENCES device(id) ON DELETE CASCADE,

    kind          TEXT    NOT NULL CHECK (kind IN ('mac','ip')),
    value         TEXT    NOT NULL,

    -- Bit local administrado ligado no primeiro octeto: (mac[0] & 0x02) != 0.
    -- Indica MAC randomizado (celular, notebook moderno) ou máquina virtual.
    -- MAC randomizado NUNCA serve como chave forte de identidade.
    is_randomized INTEGER NOT NULL DEFAULT 0 CHECK (is_randomized IN (0,1)),

    is_current    INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0,1)),
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,

    UNIQUE (device_id, kind, value)
) STRICT;

CREATE UNIQUE INDEX idx_addr_current_unique
    ON device_address (kind, value) WHERE is_current = 1;

-- Consulta quente do matcher: dado um MAC ou IP observado, achar o dispositivo.
CREATE INDEX idx_addr_lookup ON device_address (kind, value, is_current);
CREATE INDEX idx_addr_device ON device_address (device_id);


-- --------------------------------------------------------------------------
--  Serviços
--
--  Uma linha por (dispositivo, protocolo, porta). Porta que fecha recebe
--  closed_at; se reabrir, closed_at volta a NULL e last_seen é atualizado.
--  O histórico de abre/fecha vive em change_event, não aqui. A alternativa
--  (uma linha por período de abertura) multiplica o volume e complica toda
--  consulta sem ganho real.
-- --------------------------------------------------------------------------

CREATE TABLE device_service (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT    NOT NULL REFERENCES device(id) ON DELETE CASCADE,

    protocol      TEXT    NOT NULL CHECK (protocol IN ('tcp','udp')),
    port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),

    service_name  TEXT,
    banner        TEXT,
    tls_info      TEXT,          -- JSON: emissor, validade, versão, tamanho de chave

    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    closed_at     INTEGER,

    UNIQUE (device_id, protocol, port)
) STRICT;

CREATE INDEX idx_service_open ON device_service (device_id) WHERE closed_at IS NULL;
CREATE INDEX idx_service_port ON device_service (port, protocol) WHERE closed_at IS NULL;


-- --------------------------------------------------------------------------
--  Linha de base esperada
--
--  Vale mais que metade das regras genéricas. Com a linha de base definida,
--  o achado interessante deixa de ser "porta 22 aberta" e passa a ser
--  "porta 8080 apareceu e não estava prevista". Muito menos ruído.
-- --------------------------------------------------------------------------

CREATE TABLE device_baseline_port (
    device_id   TEXT    NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    protocol    TEXT    NOT NULL CHECK (protocol IN ('tcp','udp')),
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    note        TEXT,
    created_at  INTEGER NOT NULL,

    PRIMARY KEY (device_id, protocol, port)
) STRICT;


-- --------------------------------------------------------------------------
--  Observações — o dado bruto de cada varredura
--
--  device_id nasce NULL e é preenchido pelo matcher. Guardar a observação
--  crua permite reprocessar identidade se a heurística melhorar, sem
--  perder histórico. É a tabela que mais cresce: ver política de retenção.
-- --------------------------------------------------------------------------

CREATE TABLE observation (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT    NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    device_id    TEXT    REFERENCES device(id) ON DELETE SET NULL,

    ip           TEXT,
    mac          TEXT,
    hostname     TEXT,
    ttl          INTEGER,
    rtt_ms       REAL,

    method       TEXT    NOT NULL CHECK (method IN ('arp','neighbor','tcp','icmp','passive','snmp','mdns','dhcp')),
    raw          TEXT,          -- JSON com o que a sonda devolveu

    observed_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_obs_scan   ON observation (scan_id);
CREATE INDEX idx_obs_device ON observation (device_id, observed_at DESC);


-- --------------------------------------------------------------------------
--  Mudanças
--
--  Alimenta a tela de Mudanças e o histórico do dispositivo. É a razão de o
--  produto existir: um scanner responde "o que tem na rede", isto responde
--  "o que mudou desde ontem".
-- --------------------------------------------------------------------------

CREATE TABLE change_event (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id        TEXT    NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    scan_id          TEXT    REFERENCES scan(id) ON DELETE SET NULL,

    type             TEXT    NOT NULL CHECK (type IN (
                         'device_new','device_gone','device_returned',
                         'port_opened','port_closed',
                         'ip_changed','mac_changed','hostname_changed',
                         'vendor_conflict','os_changed')),

    severity         TEXT    NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),

    before           TEXT,          -- JSON
    after            TEXT,          -- JSON
    detected_at      INTEGER NOT NULL,

    acknowledged_at  INTEGER,
    acknowledged_by  TEXT
) STRICT;

CREATE INDEX idx_change_recent ON change_event (detected_at DESC);
CREATE INDEX idx_change_device ON change_event (device_id, detected_at DESC);
CREATE INDEX idx_change_open   ON change_event (detected_at DESC) WHERE acknowledged_at IS NULL;


-- --------------------------------------------------------------------------
--  Achados
--
--  `scope` distingue duas ocorrências da mesma regra no mesmo dispositivo
--  (por exemplo, NET-005 em tcp/80 e em tcp/8080). NULL quando a regra vale
--  para o dispositivo inteiro.
--
--  Achado resolvido não é apagado, é marcado. "Resolvemos 12 problemas este
--  mês" é o que prova valor e o que vira relatório depois.
--
--  severity_base vem do catálogo; severity_effective é o resultado dos
--  modificadores. Guardar as duas permite explicar na interface por que
--  aquele RDP virou alto.
-- --------------------------------------------------------------------------

CREATE TABLE finding (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id           TEXT    NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    rule_id             TEXT    NOT NULL,
    scope               TEXT,

    severity_base       TEXT    NOT NULL CHECK (severity_base IN ('critical','high','medium','low','info')),
    severity_effective  TEXT    NOT NULL CHECK (severity_effective IN ('critical','high','medium','low','info')),
    modifiers_applied   TEXT,          -- JSON, para explicar o cálculo na tela
    confidence          TEXT    NOT NULL CHECK (confidence IN ('confirmed','likely','possible')),

    evidence            TEXT,          -- JSON: o que a sonda viu

    first_seen          INTEGER NOT NULL,
    last_seen           INTEGER NOT NULL,
    resolved_at         INTEGER,

    accepted_at         INTEGER,
    accepted_by         TEXT,
    accepted_reason     TEXT,
    accepted_until      INTEGER,

    UNIQUE (device_id, rule_id, scope)
) STRICT;

CREATE INDEX idx_finding_open ON finding (severity_effective, last_seen DESC)
    WHERE resolved_at IS NULL AND accepted_at IS NULL;
CREATE INDEX idx_finding_device ON finding (device_id);
CREATE INDEX idx_finding_rule   ON finding (rule_id) WHERE resolved_at IS NULL;


-- --------------------------------------------------------------------------
--  Supressão de regra
--
--  Diferente de aceitar um achado individual: aqui a regra inteira é
--  silenciada, global ou para um dispositivo. Sem este mecanismo a lista
--  tem os mesmos quinze itens para sempre e as pessoas param de olhar.
-- --------------------------------------------------------------------------

CREATE TABLE rule_suppression (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT    NOT NULL,
    device_id   TEXT    REFERENCES device(id) ON DELETE CASCADE,  -- NULL = global
    reason      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    created_by  TEXT,
    expires_at  INTEGER
) STRICT;

CREATE UNIQUE INDEX idx_suppression_global
    ON rule_suppression (rule_id) WHERE device_id IS NULL;
CREATE UNIQUE INDEX idx_suppression_device
    ON rule_suppression (rule_id, device_id) WHERE device_id IS NOT NULL;


-- --------------------------------------------------------------------------
--  Consentimento para teste de credencial
--
--  As regras CRED-* tentam autenticar, o que pode bloquear conta e polui o
--  log do próprio cliente. O consentimento é por dispositivo, explícito,
--  com validade e registro de quem autorizou. Sem linha aqui, o motor nem
--  considera essas regras.
-- --------------------------------------------------------------------------

CREATE TABLE credential_consent (
    device_id    TEXT    NOT NULL PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
    granted_at   INTEGER NOT NULL,
    granted_by   TEXT    NOT NULL,
    expires_at   INTEGER,
    rule_scope   TEXT,          -- JSON: lista de rule_id; NULL = todas as CRED-*
    note         TEXT
) STRICT;


-- --------------------------------------------------------------------------
--  Sondas de estabilidade
--
--  rtt_ms NULL significa pacote perdido. Isso permite calcular perda e
--  jitter com uma única tabela, sem coluna separada de contagem.
-- --------------------------------------------------------------------------

CREATE TABLE probe_target (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL CHECK (kind IN ('gateway','dns_internal','dns_external','internet','custom')),
    address     TEXT    NOT NULL,
    label       TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    created_at  INTEGER NOT NULL,

    UNIQUE (kind, address)
) STRICT;

CREATE TABLE probe_sample (
    target_id  INTEGER NOT NULL REFERENCES probe_target(id) ON DELETE CASCADE,
    at         INTEGER NOT NULL,
    rtt_ms     REAL,          -- NULL = perdido

    PRIMARY KEY (target_id, at)
) STRICT, WITHOUT ROWID;

-- Agregação por minuto. A tela de 24h lê daqui, nunca da tabela crua:
-- 86 mil pontos por dia por alvo derrubam qualquer gráfico em SVG.
CREATE TABLE probe_rollup (
    target_id     INTEGER NOT NULL REFERENCES probe_target(id) ON DELETE CASCADE,
    bucket_start  INTEGER NOT NULL,
    window_s      INTEGER NOT NULL,

    samples       INTEGER NOT NULL,
    lost          INTEGER NOT NULL,
    rtt_avg       REAL,
    rtt_min       REAL,
    rtt_max       REAL,
    jitter_ms     REAL,          -- média do delta absoluto entre amostras consecutivas

    PRIMARY KEY (target_id, window_s, bucket_start)
) STRICT, WITHOUT ROWID;


-- --------------------------------------------------------------------------
--  Auditoria
--
--  Mesmo sendo ferramenta local, registre o que foi escaneado e quando.
--  Vocês vão querer isso no dia em que alguém perguntar por que a
--  impressora do financeiro imprimiu trinta páginas em branco.
-- --------------------------------------------------------------------------

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    at           INTEGER NOT NULL,
    actor        TEXT,
    action       TEXT    NOT NULL,   -- scan.start, finding.accept, consent.grant, ...
    target_type  TEXT,
    target_id    TEXT,
    detail       TEXT                -- JSON
) STRICT;

CREATE INDEX idx_audit_at ON audit_log (at DESC);


-- ==========================================================================
--  Views
-- ==========================================================================

-- Achados abertos: nem resolvidos, nem aceitos dentro da validade, nem
-- cobertos por supressão ativa. É o que a tela de Achados consome.
CREATE VIEW v_open_finding AS
SELECT f.*
FROM finding f
WHERE f.resolved_at IS NULL
  AND (f.accepted_at IS NULL OR (f.accepted_until IS NOT NULL AND f.accepted_until < unixepoch()))
  AND NOT EXISTS (
      SELECT 1 FROM rule_suppression s
      WHERE s.rule_id = f.rule_id
        AND (s.device_id IS NULL OR s.device_id = f.device_id)
        AND (s.expires_at IS NULL OR s.expires_at > unixepoch())
  );

-- Dispositivo com endereços atuais e pior severidade aberta.
-- Alimenta a lista principal e a barra colorida na borda da linha.
CREATE VIEW v_device_summary AS
SELECT
    d.id,
    d.label,
    d.kind,
    d.vendor,
    d.os_guess,
    d.identity_confidence,
    d.last_seen,
    d.miss_count,
    (SELECT value FROM device_address a
      WHERE a.device_id = d.id AND a.kind = 'ip' AND a.is_current = 1
      ORDER BY a.last_seen DESC LIMIT 1)                          AS ip,
    (SELECT value FROM device_address a
      WHERE a.device_id = d.id AND a.kind = 'mac' AND a.is_current = 1
      ORDER BY a.last_seen DESC LIMIT 1)                          AS mac,
    (SELECT COUNT(*) FROM device_service s
      WHERE s.device_id = d.id AND s.closed_at IS NULL)           AS open_ports,
    (SELECT MIN(CASE f.severity_effective
                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                  WHEN 'medium'   THEN 2 WHEN 'low'  THEN 3 ELSE 4 END)
       FROM v_open_finding f WHERE f.device_id = d.id)            AS worst_severity_rank,
    (SELECT COUNT(*) FROM v_open_finding f WHERE f.device_id = d.id) AS finding_count
FROM device d
WHERE d.is_ignored = 0;


-- ==========================================================================
--  NOTAS
-- ==========================================================================
--
--  RETENÇÃO
--
--  Três tabelas crescem sem limite e precisam de expurgo agendado:
--
--    observation    ~1 linha por dispositivo por varredura. Com 250
--                   dispositivos e varredura de hora em hora, são 6 mil
--                   linhas por dia. Expurgar conforme retention.observation_days.
--    probe_sample   1 linha por segundo por alvo. Agregue em probe_rollup e
--                   apague o cru conforme retention.probe_raw_hours.
--    change_event   cresce devagar, mas o expurgo evita que a tela de
--                   histórico fique lenta em instalação antiga.
--
--  Rode VACUUM ocasionalmente depois dos expurgos: SQLite não devolve
--  espaço ao sistema de arquivos sozinho.
--
--  --------------------------------------------------------------------
--  O MATCHER, EM TERMOS DE CONSULTA
--
--  Para cada observação, em ordem de prioridade:
--
--    1. MAC presente e is_randomized = 0
--         SELECT device_id FROM device_address
--          WHERE kind='mac' AND value=? AND is_current=1
--       → achou: confiança 'high', resolvido.
--
--    2. MAC presente mas randomizado
--       Não usar como chave forte. Tentar hostname; se não bater, criar
--       dispositivo novo com confiança 'low'.
--
--    3. Sem MAC (acontece com tudo que está fora da sub-rede local, onde
--       todos aparecem com o MAC do roteador)
--       Casar por IP + hostname → confiança 'medium'.
--       Só IP → confiança 'low', e NÃO gerar device_new com o mesmo peso,
--       ou a lista enche de fantasma.
--
--    4. Nada bateu: dispositivo novo.
--
--  Regra que economiza muita dor: decisão manual nunca é sobrescrita por
--  heurística. label_pinned = 1 ou kind_source = 'manual' são definitivos.
--
--  --------------------------------------------------------------------
--  O DIFF, AO FIM DE CADA VARREDURA, EM UMA TRANSAÇÃO
--
--    1. Resolver device_id de cada observação pelo matcher.
--    2. Atualizar last_seen, zerar miss_count, marcar endereços atuais.
--    3. Comparar serviços: abrir, fechar, gerar change_event.
--    4. Comparar identidade: IP, hostname, vendor conflitante.
--    5. Incrementar miss_count SOMENTE de quem estava no escopo coberto e
--       não apareceu. Gerar device_gone ao cruzar o limite.
--    6. Reavaliar regras, atualizar finding, marcar resolved_at no que
--       deixou de valer.
--    7. Atualizar contadores em scan e mudar status para 'completed'.
--
--  Só então emitir scan:finished para a interface.
--
--  --------------------------------------------------------------------
--  PRÓXIMA MIGRAÇÃO
--
--  0002 provavelmente traz: tabela de credencial de SNMP por dispositivo,
--  suporte a múltiplas interfaces simultâneas e um campo de site/local
--  para quando existir mais de uma sub-rede monitorada.
--
--  Nunca edite uma migração já aplicada. Crie uma nova.
