-- ============================================================================
--  Honeypot Analytics - Indices
--
--  REGRA DO PROJETO: nenhum indice entra aqui sem justificativa escrita e
--  sem um EXPLAIN ANALYZE antes/depois registrado no README.
--
--  Indice nao e de graca: ocupa disco e torna todo INSERT mais lento. Numa
--  tabela que recebe milhares de linhas por hora isso importa. Criar indice
--  "por seguranca" e o erro mais comum de quem esta comecando - e e
--  exatamente o tipo de coisa que rende conversa boa em entrevista.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
--  Nota: UNIQUE ja cria indice automaticamente. Portanto NAO precisam de
--  indice aqui: origem.ip, sessao.sessao_uid, credencial(usuario, senha),
--  comando(sessao_id, ordem), alerta(regra_id, origem_id, janela_inicio),
--  regra_deteccao.codigo, arquivo_processado.sha256.
--
--  Criar indice duplicado sobre coluna ja UNIQUE e desperdicio puro.
-- ---------------------------------------------------------------------------


-- ---------------------------------------------------------------------------
--  1. Chaves estrangeiras
--
--  O Postgres NAO indexa FK automaticamente (ao contrario do que muita gente
--  supoe). Sem indice do lado filho, todo JOIN vira sequential scan e todo
--  DELETE CASCADE no pai precisa varrer a tabela filha inteira.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_sessao_origem
    ON sessao (origem_id);

CREATE INDEX ix_tentativa_credencial
    ON tentativa (credencial_id);

CREATE INDEX ix_artefato_sessao
    ON artefato (sessao_id);

CREATE INDEX ix_alerta_origem
    ON alerta (origem_id);


-- ---------------------------------------------------------------------------
--  2. Indice composto para as regras de janela temporal
--
--  ESTE E O INDICE PRINCIPAL DO PROJETO.
--
--  Toda regra de deteccao pergunta a mesma coisa: "o que a sessao X fez
--  entre o instante A e o instante B". A ordem das colunas nao e arbitraria:
--
--    (sessao_id, ocorrido_em)  <- correto
--    (ocorrido_em, sessao_id)  <- ruim para esta carga
--
--  Indice B-tree so usa a segunda coluna depois de fixar a primeira. Como as
--  queries sempre filtram sessao_id por igualdade e ocorrido_em por intervalo,
--  igualdade vem primeiro. Inverter faz o banco varrer todas as linhas da
--  janela de tempo antes de filtrar a sessao.
--
--  Incluir `sucesso` no INCLUDE permite index-only scan na contagem de
--  falhas: o Postgres responde sem tocar na tabela.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_tentativa_sessao_tempo
    ON tentativa (sessao_id, ocorrido_em)
    INCLUDE (sucesso);


-- ---------------------------------------------------------------------------
--  3. Indice parcial: forca bruta
--
--  A regra de forca bruta so olha tentativas que FALHARAM. Como ~99.9% das
--  tentativas falham, um indice parcial aqui nao economiza muito espaco.
--  O caso inverso e que compensa muito: indexar so os SUCESSOS, que sao
--  raros e sao justamente o evento critico.
--
--  Indice parcial = so as linhas que atendem ao WHERE. Fica pequeno, cabe
--  em memoria, e o INSERT das linhas de fora nem toca nele.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_tentativa_sucesso
    ON tentativa (ocorrido_em, sessao_id)
    WHERE sucesso = TRUE;

CREATE INDEX ix_sessao_autenticada
    ON sessao (inicio DESC, origem_id)
    WHERE autenticou = TRUE;


-- ---------------------------------------------------------------------------
--  4. Ordenacao temporal do dashboard
--
--  DESC porque toda tela abre em "mais recentes primeiro". Indice na ordem
--  errada ainda funciona (o Postgres le de tras pra frente), mas com DESC
--  explicito o plano fica mais limpo e combina melhor com LIMIT.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_sessao_inicio
    ON sessao (inicio DESC);

CREATE INDEX ix_comando_tempo
    ON comando (ocorrido_em DESC);


-- ---------------------------------------------------------------------------
--  5. Fila de triagem de alertas
--
--  Parcial + composto. A tela de trabalho so mostra alerta nao fechado;
--  os fechados se acumulam pra sempre e nunca sao consultados por essa tela.
--  Manter alerta encerrado fora do indice segura o tamanho ao longo do tempo.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_alerta_fila
    ON alerta (status, detectado_em DESC)
    WHERE status IN ('novo', 'investigando');


-- ---------------------------------------------------------------------------
--  6. Busca por conteudo de comando (GIN + trigrama)
--
--  Pergunta real: "quais sessoes rodaram algo com `wget`?". Isso e
--  LIKE '%wget%', e B-tree nao serve para curinga no inicio - so um indice
--  de trigrama resolve.
--
--  Requer a extensao pg_trgm. E o indice mais caro do arquivo; so vale
--  porque investigar o playbook dos bots e um dos objetivos do projeto.
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX ix_comando_texto_trgm
    ON comando USING GIN (comando gin_trgm_ops);


-- ---------------------------------------------------------------------------
--  7. Agrupamento por infraestrutura do atacante
--
--  "De quais provedores vem mais ataque" e a analise que rende o melhor
--  grafico do dashboard. Indice parcial porque asn_org e NULL enquanto o
--  enriquecimento nao rodou, e linha NULL nunca aparece nesse agrupamento.
-- ---------------------------------------------------------------------------

CREATE INDEX ix_origem_asn
    ON origem (asn_org, pais)
    WHERE asn_org IS NOT NULL;

COMMIT;

-- ---------------------------------------------------------------------------
--  Verificacao pos-carga: quais indices estao sendo realmente usados?
--  Rode depois de alguns dias de dados. idx_scan = 0 significa indice
--  inutil - e remover um indice inutil e uma otima linha de README.
--
--    SELECT relname, indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid))
--    FROM pg_stat_user_indexes
--    ORDER BY idx_scan ASC;
-- ---------------------------------------------------------------------------
