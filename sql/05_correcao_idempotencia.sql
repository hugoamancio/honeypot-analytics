-- ============================================================================
--  Migration 05 - Fecha o furo de idempotencia em `tentativa` e `artefato`
--
--  CONTEXTO (vale no README - foi bug real, achado por teste real)
--
--  As duas tabelas nasceram sem chave natural. O raciocinio original era que
--  o controle por hash de arquivo (`arquivo_processado`) bastaria. Nao basta:
--
--    - o cowrie.json CRESCE durante o dia;
--    - arquivo maior => hash diferente => passa pela checagem de arquivo;
--    - as sessoes antigas reaparecem no parse;
--    - `sessao` se protege com ON CONFLICT (sessao_uid) e devolve o id que
--      ja existia;
--    - e entao TODAS as tentativas daquelas sessoes sao inseridas de novo.
--
--  Resultado medido: reprocessar o mesmo arquivo dobrou `tentativa` de
--  5.916 para 11.832 linhas. Nao era hipotese - foi observado.
--
--  CORRECAO
--  Chave natural explicita nas duas tabelas. A trinca escolhida e unica na
--  pratica porque o Cowrie carimba timestamp com precisao de microssegundo:
--  duas tentativas identicas, na mesma sessao, no mesmo microssegundo, com a
--  mesma credencial, nao ocorrem. E se ocorressem, perder uma seria inocuo.
--
--  Aplicar em banco ja existente:
--    docker exec -i honeypot_db psql -U analista -d honeypot < sql/05_correcao_idempotencia.sql
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
--  1. Limpar as duplicatas ja gravadas
--
--  Mantem a linha de menor id em cada grupo e descarta as demais. O
--  self-join com `t.id > t2.id` e a forma classica: uma linha so sobrevive
--  se nao existir outra igual com id menor.
-- ---------------------------------------------------------------------------

DELETE FROM tentativa t
      USING tentativa t2
      WHERE t.id            >  t2.id
        AND t.sessao_id     =  t2.sessao_id
        AND t.credencial_id =  t2.credencial_id
        AND t.ocorrido_em   =  t2.ocorrido_em;

DELETE FROM artefato a
      USING artefato a2
      WHERE a.id          >  a2.id
        AND a.sessao_id   =  a2.sessao_id
        AND a.sha256      =  a2.sha256
        AND a.ocorrido_em =  a2.ocorrido_em;


-- ---------------------------------------------------------------------------
--  2. Impedir que volte a acontecer
--
--  A partir daqui a garantia e do banco, nao da disciplina de quem chama.
--  E o ponto central: regra que depende de alguem lembrar de aplicar nao e
--  garantia, e torcida.
-- ---------------------------------------------------------------------------

--  Os blocos DO existem porque este arquivo roda em DOIS cenarios:
--    - banco novo: o 01_schema.sql ja criou as constraints, e aqui nao ha
--      nada a fazer (ADD CONSTRAINT direto abortaria com "ja existe");
--    - banco antigo: as constraints faltam e precisam ser criadas.
--  Sem essa checagem, `docker compose up` num volume limpo falharia.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'tentativa_evento_unico') THEN
        ALTER TABLE tentativa
            ADD CONSTRAINT tentativa_evento_unico
            UNIQUE (sessao_id, credencial_id, ocorrido_em);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'artefato_evento_unico') THEN
        ALTER TABLE artefato
            ADD CONSTRAINT artefato_evento_unico
            UNIQUE (sessao_id, sha256, ocorrido_em);
    END IF;
END $$;


-- ---------------------------------------------------------------------------
--  3. Indice que virou redundante
--
--  A UNIQUE nova cria indice em (sessao_id, credencial_id, ocorrido_em), cujo
--  prefixo (sessao_id, ...) ja atende as consultas por sessao. O antigo
--  ix_tentativa_sessao_tempo passa a ser peso morto no INSERT.
--
--  Mantido por ora: ele tem INCLUDE (sucesso), o que permite index-only scan
--  na contagem de falhas - coisa que a UNIQUE nao faz. Decidir com dado real,
--  olhando idx_scan em pg_stat_user_indexes depois de alguns dias.
-- ---------------------------------------------------------------------------

COMMIT;
