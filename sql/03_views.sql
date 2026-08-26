-- ============================================================================
--  Honeypot Analytics - Views
--
--  O dashboard le SO daqui, nunca das tabelas direto. Assim o Streamlit fica
--  fino (chama a view, plota) e a logica analitica mora no banco, versionada
--  em git, testavel via psql, reaproveitavel pela API.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
--  vw_top_credenciais - o ranking mais citavel do projeto
--
--  Aqui aparece o achado que rende a melhor frase de README: uma fracao
--  minuscula de senhas responde pela maioria esmagadora das tentativas.
-- ---------------------------------------------------------------------------

CREATE VIEW vw_top_credenciais AS
SELECT
    c.usuario,
    c.senha,
    COUNT(*)                                   AS tentativas,
    COUNT(DISTINCT s.origem_id)                AS ips_distintos,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 3) AS pct_do_total
FROM tentativa t
JOIN credencial c ON c.id = t.credencial_id
JOIN sessao     s ON s.id = t.sessao_id
GROUP BY c.usuario, c.senha
ORDER BY tentativas DESC;


-- ---------------------------------------------------------------------------
--  vw_atividade_horaria - serie temporal do dashboard
--
--  date_trunc agrega por hora. generate_series nao entra aqui de proposito:
--  hora sem ataque simplesmente nao existe (e, na pratica, quase nao ocorre).
-- ---------------------------------------------------------------------------

CREATE VIEW vw_atividade_horaria AS
SELECT
    date_trunc('hour', s.inicio)    AS hora,
    s.protocolo,
    COUNT(DISTINCT s.id)            AS sessoes,
    COUNT(DISTINCT s.origem_id)     AS ips_unicos,
    COUNT(t.id)                     AS tentativas
FROM sessao s
LEFT JOIN tentativa t ON t.sessao_id = s.id
GROUP BY 1, 2
ORDER BY 1 DESC;


-- ---------------------------------------------------------------------------
--  vw_infra_atacante - de onde saem os ataques
--
--  Agrupa por ASN, nao por pais. Pais e a metrica ingenua: diz "China" e
--  para por ai. ASN diz QUAL provedor - e a concentracao em poucos provedores
--  de VPS barato e o achado que realmente vale contar.
-- ---------------------------------------------------------------------------

CREATE VIEW vw_infra_atacante AS
SELECT
    COALESCE(o.asn_org, '(nao enriquecido)') AS organizacao,
    o.pais,
    COUNT(DISTINCT o.id)        AS ips,
    COUNT(DISTINCT s.id)        AS sessoes,
    MIN(o.primeiro_visto)       AS visto_desde
FROM origem o
LEFT JOIN sessao s ON s.origem_id = o.id
GROUP BY 1, 2
ORDER BY sessoes DESC;


-- ---------------------------------------------------------------------------
--  vw_playbook_inicial - os 5 primeiros comandos de cada sessao
--
--  A view mais interessante do projeto. Reconstroi o que o bot faz nos
--  primeiros segundos depois de achar que invadiu. Rodando um GROUP BY em
--  cima de `roteiro`, aparecem os playbooks repetidos - familias de botnet
--  distintas emergem sozinhas dos dados.
-- ---------------------------------------------------------------------------

CREATE VIEW vw_playbook_inicial AS
WITH primeiros AS (
    SELECT
        c.sessao_id,
        c.ordem,
        c.comando,
        c.ocorrido_em,
        ROW_NUMBER() OVER (PARTITION BY c.sessao_id ORDER BY c.ordem) AS rn
    FROM comando c
)
SELECT
    p.sessao_id,
    o.ip,
    o.pais,
    MIN(s.inicio)                                   AS sessao_iniciada,
    -- segundos entre "login" e o primeiro comando: humano hesita, bot nao
    EXTRACT(EPOCH FROM (MIN(p.ocorrido_em) - MIN(s.inicio)))::NUMERIC(10,2)
                                                    AS latencia_1o_comando,
    string_agg(p.comando, ' ; ' ORDER BY p.ordem)   AS roteiro
FROM primeiros p
JOIN sessao s ON s.id = p.sessao_id
JOIN origem o ON o.id = s.origem_id
WHERE p.rn <= 5
GROUP BY p.sessao_id, o.ip, o.pais;


-- ---------------------------------------------------------------------------
--  vw_alertas_abertos - fila de triagem
-- ---------------------------------------------------------------------------

CREATE VIEW vw_alertas_abertos AS
SELECT
    a.id,
    r.codigo            AS regra,
    r.nome              AS regra_nome,
    r.mitre_tecnica,
    r.severidade,
    o.ip,
    o.pais,
    o.asn_org,
    a.janela_inicio,
    a.janela_fim,
    a.detectado_em,
    a.status,
    a.evidencia
FROM alerta a
JOIN regra_deteccao r ON r.id = a.regra_id
JOIN origem         o ON o.id = a.origem_id
WHERE a.status IN ('novo', 'investigando')
ORDER BY
    -- ENUM ordena pela ordem de declaracao, entao inverter aqui poe
    -- 'critica' no topo sem precisar de CASE manual.
    r.severidade DESC,
    a.detectado_em DESC;

COMMIT;
