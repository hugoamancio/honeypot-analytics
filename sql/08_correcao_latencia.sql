-- ============================================================================
--  Migration 08 - Corrige o marco zero da latencia em vw_playbook_inicial
--
--  BUG (encontrado ao olhar o grafico, nao ao ler o codigo)
--
--  A versao anterior calculava:
--
--      primeiro_comando - sessao.inicio
--
--  `sessao.inicio` e o instante da CONEXAO. Entre a conexao e o primeiro
--  comando cabem todas as tentativas de login que falharam - numa sessao de
--  60 tentativas, uns 80 segundos so de forca bruta. O numero resultante nao
--  era "tempo de reacao do atacante", era "tempo de conexao + duracao do
--  ataque de senha". O grafico mostrava ate 300s onde o esperado era ~1s.
--
--  O erro estava no ROTULO tanto quanto na conta: a coluna se chamava
--  latencia_1o_comando e a legenda dizia "entre o login e o 1o comando".
--  Metrica com nome errado e pior que metrica ausente - ela e citada em
--  entrevista e desmorona na primeira pergunta.
--
--  CORRECAO
--      primeiro_comando - instante_da_autenticacao_bem_sucedida
--
--  Agora mede o que o nome promete: quanto tempo o atacante levou para agir
--  DEPOIS de achar que entrou. E ai o valor volta a ser a fracao de segundo
--  que distingue bot de humano.
-- ============================================================================

BEGIN;

CREATE OR REPLACE VIEW vw_playbook_inicial AS
WITH primeiros AS (
    SELECT c.sessao_id,
           c.ordem,
           c.comando,
           c.ocorrido_em,
           ROW_NUMBER() OVER (PARTITION BY c.sessao_id ORDER BY c.ordem) AS rn
    FROM comando c
),
-- Marco zero correto: o instante em que a sessao autenticou. MAX porque o
-- sucesso e sempre a ultima tentativa da sessao.
login AS (
    SELECT sessao_id, MAX(ocorrido_em) AS autenticou_em
    FROM tentativa
    WHERE sucesso = TRUE
    GROUP BY sessao_id
)
SELECT p.sessao_id,
       o.ip,
       o.pais,
       MIN(s.inicio) AS sessao_iniciada,
       -- COALESCE para o caso de comando sem login registrado (log cortado):
       -- cai no comportamento antigo em vez de virar NULL silencioso.
       EXTRACT(EPOCH FROM (
           MIN(p.ocorrido_em) - COALESCE(MIN(l.autenticou_em), MIN(s.inicio))
       ))::NUMERIC(10,2) AS latencia_1o_comando,
       string_agg(p.comando, ' ; ' ORDER BY p.ordem) AS roteiro
FROM primeiros p
JOIN sessao s ON s.id = p.sessao_id
JOIN origem o ON o.id = s.origem_id
LEFT JOIN login l ON l.sessao_id = p.sessao_id
WHERE p.rn <= 5
GROUP BY p.sessao_id, o.ip, o.pais;

COMMIT;
