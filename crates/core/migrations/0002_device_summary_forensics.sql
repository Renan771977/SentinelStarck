-- ==========================================================================
--  0002 — dados de investigação na view de resumo
--
--  A view original não expunha `first_seen` nem `hostname`. Os dois são
--  centrais para investigação: "quando este dispositivo apareceu pela
--  primeira vez nesta rede" é a primeira pergunta de qualquer apuração, e
--  hostname costuma ser a única pista de identidade quando o MAC é
--  randomizado.
--
--  Nunca edite uma migração já aplicada. Esta recria a view; recriar view é
--  seguro porque ela não guarda dado, só a consulta.
-- ==========================================================================

DROP VIEW IF EXISTS v_device_summary;

CREATE VIEW v_device_summary AS
SELECT
    d.id,
    d.label,
    d.kind,
    d.vendor,
    d.hostname,
    d.os_guess,
    d.identity_confidence,
    d.first_seen,
    d.last_seen,
    d.miss_count,
    (SELECT value FROM device_address a
      WHERE a.device_id = d.id AND a.kind = 'ip' AND a.is_current = 1
      ORDER BY a.last_seen DESC LIMIT 1)                          AS ip,
    (SELECT value FROM device_address a
      WHERE a.device_id = d.id AND a.kind = 'mac' AND a.is_current = 1
      ORDER BY a.last_seen DESC LIMIT 1)                          AS mac,
    -- Quantos endereços diferentes este dispositivo já teve. Valor alto
    -- indica DHCP instável ou, em investigação, tentativa de evasão.
    (SELECT COUNT(*) FROM device_address a
      WHERE a.device_id = d.id AND a.kind = 'ip')                 AS ip_history_count,
    (SELECT COUNT(*) FROM device_service s
      WHERE s.device_id = d.id AND s.closed_at IS NULL)           AS open_ports,
    (SELECT MIN(CASE f.severity_effective
                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                  WHEN 'medium'   THEN 2 WHEN 'low'  THEN 3 ELSE 4 END)
       FROM v_open_finding f WHERE f.device_id = d.id)            AS worst_severity_rank,
    (SELECT COUNT(*) FROM v_open_finding f WHERE f.device_id = d.id) AS finding_count
FROM device d
WHERE d.is_ignored = 0;