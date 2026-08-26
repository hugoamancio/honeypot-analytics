-- ============================================================================
--  Honeypot Analytics - As 11 regras de deteccao
--
--  CONTRATO
--  Toda view aqui devolve exatamente estas 4 colunas:
--
--      origem_id      BIGINT       quem disparou
--      janela_inicio  TIMESTAMPTZ  inicio do periodo observado
--      janela_fim     TIMESTAMPTZ  fim (sempre > inicio, por causa do CHECK)
--      evidencia      JSONB        os numeros que sustentam o alerta
--
--  O executor (pipeline/detectar.py) nao sabe NADA sobre o conteudo das
--  regras: ele le o catalogo em `regra_deteccao`, monta o nome da view a
--  partir do codigo e faz INSERT ... SELECT com ON CONFLICT. Regra nova =
--  uma view + uma linha no catalogo. Zero mudanca no Python.
--
--  GREATEST(..., inicio + interval '1 second') aparece em toda regra: o
--  CHECK alerta_janela_coerente exige fim > inicio, e evento instantaneo
--  teria fim = inicio.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
--  1. BRUTE_FORCE_SSH  (T1110.001)
--     20+ falhas do mesmo IP em janela de 5 minutos.
--
--     Usa JANELA DESLIZANTE de verdade (RANGE BETWEEN INTERVAL), nao balde
--     fixo. Diferenca pratica: um ataque que comeca 23:59 e termina 00:01
--     seria partido em dois baldes e talvez nenhum atingisse o limiar. A
--     deslizante pega. Depois agrupa por hora so para nao gerar um alerta
--     por tentativa - o alerta e o pico da hora.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_brute_force_ssh AS
WITH falhas AS (
    SELECT s.origem_id, t.ocorrido_em
    FROM tentativa t
    JOIN sessao s ON s.id = t.sessao_id
    WHERE t.sucesso = FALSE
),
deslizante AS (
    SELECT origem_id, ocorrido_em,
           COUNT(*) OVER (
               PARTITION BY origem_id
               ORDER BY ocorrido_em
               RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
           ) AS n_janela
    FROM falhas
)
SELECT origem_id,
       MIN(ocorrido_em) AS janela_inicio,
       GREATEST(MAX(ocorrido_em), MIN(ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'pico_em_5min', MAX(n_janela),
           'falhas_na_hora', COUNT(*),
           'limiar', 20
       ) AS evidencia
FROM deslizante
WHERE n_janela >= 20
GROUP BY origem_id, date_trunc('hour', ocorrido_em);


-- ---------------------------------------------------------------------------
--  2. PASSWORD_SPRAY  (T1110.003)
--     Mesma senha contra 10+ usuarios distintos, no mesmo dia.
--
--     Padrao INVERSO da forca bruta: em vez de muitas senhas num usuario,
--     poucas senhas em muitos usuarios - justamente para nao estourar o
--     bloqueio por conta. Regra de forca bruta nao pega isso.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_password_spray AS
SELECT s.origem_id,
       MIN(t.ocorrido_em) AS janela_inicio,
       GREATEST(MAX(t.ocorrido_em), MIN(t.ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'senha', c.senha,
           'usuarios_distintos', COUNT(DISTINCT c.usuario),
           'tentativas', COUNT(*),
           'limiar', 10
       ) AS evidencia
FROM tentativa t
JOIN sessao     s ON s.id = t.sessao_id
JOIN credencial c ON c.id = t.credencial_id
GROUP BY s.origem_id, c.senha, date_trunc('day', t.ocorrido_em)
HAVING COUNT(DISTINCT c.usuario) >= 10;


-- ---------------------------------------------------------------------------
--  3. CREDENCIAL_VALIDA_USADA  (T1078)  [critica]
--     Qualquer autenticacao bem-sucedida.
--
--     Em honeypot todo login e simulado - nao existe credencial legitima.
--     Logo qualquer sucesso e, por definicao, evento de interesse maximo.
--     Num servidor real esta regra seria ruidosa; aqui ela e exata.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_credencial_valida_usada AS
SELECT s.origem_id,
       s.inicio AS janela_inicio,
       GREATEST(COALESCE(s.fim, s.inicio), s.inicio + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_uid', s.sessao_uid,
           'usuario', c.usuario,
           'senha', c.senha,
           'cliente', s.cliente_versao,
           'comandos_executados', (SELECT COUNT(*) FROM comando cm WHERE cm.sessao_id = s.id)
       ) AS evidencia
FROM sessao s
JOIN tentativa  t ON t.sessao_id = s.id AND t.sucesso = TRUE
JOIN credencial c ON c.id = t.credencial_id
WHERE s.autenticou = TRUE;


-- ---------------------------------------------------------------------------
--  4. DOWNLOAD_ARTEFATO  (T1105)  [critica]
--     Sessao trouxe arquivo de fora.
--
--     Cobre os dois sinais: o download que o Cowrie capturou (tabela
--     artefato) e o comando de busca (wget/curl/tftp). Os dois porque o
--     download pode falhar - o C2 ja caiu, a URL morreu - e a INTENCAO
--     continua sendo o que importa detectar.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_download_artefato AS
WITH sinais AS (
    SELECT s.origem_id, s.id AS sessao_id, a.ocorrido_em,
           a.url, a.sha256
    FROM artefato a
    JOIN sessao s ON s.id = a.sessao_id
    UNION ALL
    SELECT s.origem_id, s.id, cm.ocorrido_em,
           cm.comando AS url, NULL AS sha256
    FROM comando cm
    JOIN sessao s ON s.id = cm.sessao_id
    WHERE cm.comando ~* '(^|[;&|[:space:]])(wget|curl|tftp)[[:space:]]'
)
SELECT origem_id,
       MIN(ocorrido_em) AS janela_inicio,
       GREATEST(MAX(ocorrido_em), MIN(ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_id', sessao_id,
           'ocorrencias', COUNT(*),
           'alvos', jsonb_agg(DISTINCT url),
           'hashes', jsonb_agg(DISTINCT sha256) FILTER (WHERE sha256 IS NOT NULL)
       ) AS evidencia
FROM sinais
GROUP BY origem_id, sessao_id;


-- ---------------------------------------------------------------------------
--  5. RECON_SISTEMA  (T1082)  [baixa]
--     3+ comandos de descoberta na mesma sessao.
--
--     Um `uname` isolado nao significa nada. Tres comandos de reconhecimento
--     seguidos sao o bot medindo o que acabou de "invadir" - decidindo se a
--     maquina vale minerar. O limiar de 3 e o que separa ruido de padrao.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_recon_sistema AS
SELECT s.origem_id,
       MIN(cm.ocorrido_em) AS janela_inicio,
       GREATEST(MAX(cm.ocorrido_em), MIN(cm.ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_id', s.id,
           'comandos_recon', COUNT(*),
           'quais', jsonb_agg(cm.comando ORDER BY cm.ordem),
           'limiar', 3
       ) AS evidencia
FROM comando cm
JOIN sessao s ON s.id = cm.sessao_id
WHERE cm.comando ~* '(uname|whoami|/proc/cpuinfo|nproc|lscpu|free[[:space:]]+-|id$|hostname)'
GROUP BY s.origem_id, s.id
HAVING COUNT(*) >= 3;


-- ---------------------------------------------------------------------------
--  6. PERSISTENCIA_SSH_KEY  (T1098.004)  [critica]
--     Grava chave, cron ou rc.local para garantir retorno.
--
--     Das mais graves: trocar a senha nao expulsa quem plantou chave em
--     authorized_keys.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_persistencia_ssh_key AS
SELECT s.origem_id,
       MIN(cm.ocorrido_em) AS janela_inicio,
       GREATEST(MAX(cm.ocorrido_em), MIN(cm.ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_id', s.id,
           'comandos', jsonb_agg(cm.comando ORDER BY cm.ordem),
           'mecanismo', CASE
               WHEN bool_or(cm.comando ~* 'authorized_keys') THEN 'chave_ssh'
               WHEN bool_or(cm.comando ~* 'cron')            THEN 'cron'
               ELSE 'script_de_boot'
           END
       ) AS evidencia
FROM comando cm
JOIN sessao s ON s.id = cm.sessao_id
WHERE cm.comando ~* '(authorized_keys|crontab|/etc/cron|rc\.local|systemd/system)'
GROUP BY s.origem_id, s.id;


-- ---------------------------------------------------------------------------
--  7. DESATIVACAO_DEFESA  (T1562.001)
--     Derruba firewall, SELinux ou antivirus antes de agir.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_desativacao_defesa AS
SELECT s.origem_id,
       MIN(cm.ocorrido_em) AS janela_inicio,
       GREATEST(MAX(cm.ocorrido_em), MIN(cm.ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_id', s.id,
           'comandos', jsonb_agg(cm.comando ORDER BY cm.ordem),
           'quantidade', COUNT(*)
       ) AS evidencia
FROM comando cm
JOIN sessao s ON s.id = cm.sessao_id
WHERE cm.comando ~* '(iptables[[:space:]]+-F|ufw[[:space:]]+disable|setenforce[[:space:]]+0|stop[[:space:]]+(firewalld|iptables|apparmor)|systemctl[[:space:]]+(stop|disable)[[:space:]]+firewall)'
GROUP BY s.origem_id, s.id;


-- ---------------------------------------------------------------------------
--  8. LIMPEZA_RASTRO  (T1070.003)
--     Apaga historico e log - sinal de operador consciente, nao de bot burro.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_limpeza_rastro AS
SELECT s.origem_id,
       MIN(cm.ocorrido_em) AS janela_inicio,
       GREATEST(MAX(cm.ocorrido_em), MIN(cm.ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_id', s.id,
           'comandos', jsonb_agg(cm.comando ORDER BY cm.ordem)
       ) AS evidencia
FROM comando cm
JOIN sessao s ON s.id = cm.sessao_id
WHERE cm.comando ~* '(history[[:space:]]+-c|\.bash_history|>[[:space:]]*/var/log|rm[[:space:]]+.*(/var/log|wtmp|utmp|lastlog))'
GROUP BY s.origem_id, s.id;


-- ---------------------------------------------------------------------------
--  9. MINERACAO_CRIPTO  (T1496)
--     Minerador ou pool de mineracao.
--
--     O motivo economico mais comum por tras da invasao de servidor exposto:
--     a maquina nao interessa pelos dados, interessa pela CPU.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_mineracao_cripto AS
SELECT s.origem_id,
       MIN(cm.ocorrido_em) AS janela_inicio,
       GREATEST(MAX(cm.ocorrido_em), MIN(cm.ocorrido_em) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessao_id', s.id,
           'comandos', jsonb_agg(cm.comando ORDER BY cm.ordem),
           'indicador', CASE
               WHEN bool_or(cm.comando ~* '(stratum|pool[[:alnum:].]*:[0-9]+|minexmr|nanopool|f2pool)') THEN 'pool'
               ELSE 'binario_minerador'
           END
       ) AS evidencia
FROM comando cm
JOIN sessao s ON s.id = cm.sessao_id
WHERE cm.comando ~* '(xmrig|minerd|cpuminer|cgminer|ethminer|stratum\+tcp|minexmr|nanopool|f2pool|--donate-level)'
GROUP BY s.origem_id, s.id;


-- ---------------------------------------------------------------------------
--  10. REINCIDENTE
--      5+ sessoes do mesmo IP em 24h.
--
--      Separa varredura oportunista (bate uma vez, some) de interesse
--      dirigido no alvo. Sem tecnica MITRE porque nao e uma tecnica: e um
--      padrao de comportamento.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_reincidente AS
SELECT origem_id,
       MIN(inicio) AS janela_inicio,
       GREATEST(MAX(inicio), MIN(inicio) + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessoes_no_dia', COUNT(*),
           'autenticou_alguma', bool_or(autenticou),
           'limiar', 5
       ) AS evidencia
FROM sessao
GROUP BY origem_id, date_trunc('day', inicio)
HAVING COUNT(*) >= 5;


-- ---------------------------------------------------------------------------
--  11. HORARIO_REGULAR  [baixa]
--      Cadencia estatisticamente regular = tarefa agendada, nao humano.
--
--      A METRICA: coeficiente de variacao dos intervalos entre sessoes
--      (desvio padrao / media). Humano e irregular - CV alto. Cron e
--      metronomo - CV proximo de zero. Abaixo de 0.15 nao ha operador
--      humano plausivel.
--
--      Usa a MEDIA como divisor em vez de comparar desvio absoluto: assim
--      a regra funciona igual para cadencia de 5 minutos e de 6 horas.
-- ---------------------------------------------------------------------------

CREATE VIEW regra_horario_regular AS
WITH ordenadas AS (
    SELECT origem_id, inicio,
           LAG(inicio) OVER (PARTITION BY origem_id ORDER BY inicio) AS anterior
    FROM sessao
),
intervalos AS (
    SELECT origem_id, inicio,
           EXTRACT(EPOCH FROM (inicio - anterior)) AS gap_seg
    FROM ordenadas
    WHERE anterior IS NOT NULL
),
resumo AS (
    SELECT origem_id,
           COUNT(*)            AS n_intervalos,
           AVG(gap_seg)        AS media,
           STDDEV_POP(gap_seg) AS desvio,
           MIN(inicio)         AS ini,
           MAX(inicio)         AS fim
    FROM intervalos
    GROUP BY origem_id
)
SELECT origem_id,
       ini AS janela_inicio,
       GREATEST(fim, ini + INTERVAL '1 second') AS janela_fim,
       jsonb_build_object(
           'sessoes', n_intervalos + 1,
           'intervalo_medio_min', ROUND((media / 60)::numeric, 1),
           'desvio_seg', ROUND(desvio::numeric, 1),
           'coef_variacao', ROUND((desvio / NULLIF(media, 0))::numeric, 4),
           'limiar_cv', 0.15
       ) AS evidencia
FROM resumo
WHERE n_intervalos >= 7           -- amostra pequena demais nao sustenta a conclusao
  AND media > 60                  -- rajada dentro do mesmo minuto nao e cadencia
  AND desvio / NULLIF(media, 0) < 0.15;

COMMIT;
