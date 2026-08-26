-- ============================================================================
--  Honeypot Analytics - Views de apoio ao dashboard
--
--  Regra do projeto: a camada de apresentacao NAO consulta tabela direto.
--  Toda agregacao vive aqui, versionada em git e testavel no psql. O
--  Streamlit so chama a view e desenha.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
--  vw_resumo - os numeros do topo da tela (uma unica linha)
--
--  Subquery escalar por metrica, em vez de varios JOINs: cada contagem e
--  independente e o planejador resolve cada uma no seu proprio indice. Uma
--  linha so, entao o custo de repetir a leitura e irrelevante.
-- ---------------------------------------------------------------------------

CREATE VIEW vw_resumo AS
SELECT
    (SELECT COUNT(*) FROM sessao)                         AS sessoes,
    (SELECT COUNT(*) FROM origem)                         AS ips,
    (SELECT COUNT(*) FROM tentativa)                      AS tentativas,
    (SELECT COUNT(*) FROM sessao WHERE autenticou)        AS autenticadas,
    (SELECT COUNT(*) FROM comando)                        AS comandos,
    (SELECT COUNT(*) FROM artefato)                       AS artefatos,
    (SELECT COUNT(*) FROM alerta
      WHERE status IN ('novo', 'investigando'))           AS alertas_abertos,
    (SELECT COUNT(*) FROM alerta a
       JOIN regra_deteccao r ON r.id = a.regra_id
      WHERE r.severidade = 'critica'
        AND a.status IN ('novo', 'investigando'))         AS alertas_criticos,
    (SELECT MIN(inicio) FROM sessao)                      AS coleta_desde,
    (SELECT MAX(inicio) FROM sessao)                      AS coleta_ate;


-- ---------------------------------------------------------------------------
--  vw_alertas_por_regra - quanto cada regra produziu
--
--  LEFT JOIN de proposito: regra que nao disparou precisa aparecer com zero.
--  Regra silenciosa e indistinguivel de regra quebrada - foi assim que tres
--  regras mudas foram detectadas neste projeto. Esconde-la seria apagar o
--  sinal mais util da tela.
-- ---------------------------------------------------------------------------

CREATE VIEW vw_alertas_por_regra AS
SELECT r.codigo,
       r.nome,
       r.mitre_tecnica,
       r.severidade,
       r.ativa,
       COUNT(a.id)                  AS alertas,
       COUNT(DISTINCT a.origem_id)  AS ips_envolvidos,
       MAX(a.detectado_em)          AS ultimo_disparo
FROM regra_deteccao r
LEFT JOIN alerta a ON a.regra_id = r.id
GROUP BY r.id, r.codigo, r.nome, r.mitre_tecnica, r.severidade, r.ativa;


-- ---------------------------------------------------------------------------
--  vw_concentracao_senhas - a estatistica mais citavel do projeto
--
--  Responde "quantas senhas distintas bastam para cobrir N% das tentativas".
--  A curva costuma ser brutal: uma duzia de senhas cobre a maioria esmagadora
--  do trafego de ataque. Isso e um argumento pratico de politica de senha,
--  nao uma curiosidade.
-- ---------------------------------------------------------------------------

CREATE VIEW vw_concentracao_senhas AS
WITH ranking AS (
    SELECT c.senha,
           COUNT(*) AS tentativas,
           ROW_NUMBER() OVER (ORDER BY COUNT(*) DESC) AS posicao
    FROM tentativa t
    JOIN credencial c ON c.id = t.credencial_id
    GROUP BY c.senha
)
SELECT posicao,
       senha,
       tentativas,
       SUM(tentativas) OVER (ORDER BY posicao) AS acumulado,
       ROUND(100.0 * SUM(tentativas) OVER (ORDER BY posicao)
             / NULLIF(SUM(tentativas) OVER (), 0), 2) AS pct_acumulado
FROM ranking;

COMMIT;
