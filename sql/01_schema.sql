-- ============================================================================
--  Honeypot Analytics - Schema
--  PostgreSQL 15+
--
--  Modelo relacional para ingestao e analise de tentativas de intrusao
--  capturadas por um honeypot SSH/Telnet (Cowrie).
--
--  Ordem de execucao:
--    01_schema.sql -> 02_indices.sql -> 03_views.sql -> 04_seed_regras.sql
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
--  Tipos enumerados
--
--  ENUM em vez de VARCHAR + CHECK: o banco recusa valor invalido, ocupa 4
--  bytes, e o conjunto de valores fica documentado no proprio schema.
--  Custo: incluir valor novo exige ALTER TYPE (aceitavel, muda pouco).
-- ---------------------------------------------------------------------------

CREATE TYPE protocolo_honeypot AS ENUM ('ssh', 'telnet');

CREATE TYPE severidade_alerta  AS ENUM ('baixa', 'media', 'alta', 'critica');

CREATE TYPE status_alerta      AS ENUM ('novo', 'investigando', 'fechado', 'falso_positivo');


-- ---------------------------------------------------------------------------
--  origem - o endereco IP que atacou
--
--  Uma linha por IP distinto. Enriquecida com geolocalizacao e ASN (o "dono"
--  do bloco de rede: provedor, cloud, universidade). O ASN costuma ser o
--  campo mais revelador: boa parte dos ataques sai de um punhado de
--  provedores de VPS baratos.
-- ---------------------------------------------------------------------------

CREATE TABLE origem (
    id              BIGSERIAL   PRIMARY KEY,
    ip              INET        NOT NULL,
    pais            CHAR(2),
    asn             INTEGER,
    asn_org         TEXT,
    primeiro_visto  TIMESTAMPTZ NOT NULL,
    ultimo_visto    TIMESTAMPTZ NOT NULL,
    criado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT origem_ip_unico
        UNIQUE (ip),

    -- INET tambem aceita rede (10.0.0.0/8). Aqui cada linha e UM host:
    -- mascara cheia, /32 em IPv4 e /128 em IPv6.
    CONSTRAINT origem_ip_e_host
        CHECK (masklen(ip) = CASE family(ip) WHEN 4 THEN 32 ELSE 128 END),

    -- ISO 3166-1 alpha-2, sempre maiusculo. Evita 'br' e 'BR' convivendo.
    CONSTRAINT origem_pais_iso
        CHECK (pais IS NULL OR pais ~ '^[A-Z]{2}$'),

    CONSTRAINT origem_asn_positivo
        CHECK (asn IS NULL OR asn > 0),

    CONSTRAINT origem_janela_coerente
        CHECK (ultimo_visto >= primeiro_visto)
);

COMMENT ON TABLE  origem         IS 'IP de origem dos ataques, com enriquecimento de geo/ASN.';
COMMENT ON COLUMN origem.asn_org IS 'Organizacao dona do ASN - agrupar por aqui revela a infra usada pelos bots.';


-- ---------------------------------------------------------------------------
--  sessao - uma conexao completa com o honeypot
--
--  sessao_uid e o identificador que o proprio Cowrie gera. Guardar isso com
--  UNIQUE e o que torna a ingestao IDEMPOTENTE: reprocessar o mesmo arquivo
--  de log nao duplica dados (ON CONFLICT DO NOTHING).
-- ---------------------------------------------------------------------------

CREATE TABLE sessao (
    id              BIGSERIAL   PRIMARY KEY,
    sessao_uid      TEXT        NOT NULL,
    origem_id       BIGINT      NOT NULL,
    protocolo       protocolo_honeypot NOT NULL,
    porta_destino   INTEGER     NOT NULL,
    cliente_versao  TEXT,
    inicio          TIMESTAMPTZ NOT NULL,
    fim             TIMESTAMPTZ,
    autenticou      BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Coluna gerada: o banco calcula e mantem sozinho. Nao consegue ficar
    -- dessincronizada, ao contrario de uma coluna preenchida pela aplicacao.
    duracao_seg     NUMERIC(10,3)
        GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (fim - inicio))) STORED,

    CONSTRAINT sessao_uid_unico
        UNIQUE (sessao_uid),

    CONSTRAINT sessao_origem_fk
        FOREIGN KEY (origem_id) REFERENCES origem (id)
        ON DELETE CASCADE,

    CONSTRAINT sessao_porta_valida
        CHECK (porta_destino BETWEEN 1 AND 65535),

    CONSTRAINT sessao_fim_apos_inicio
        CHECK (fim IS NULL OR fim >= inicio)
);

COMMENT ON COLUMN sessao.sessao_uid     IS 'ID nativo do Cowrie. Chave natural que garante ingestao idempotente.';
COMMENT ON COLUMN sessao.cliente_versao IS 'Banner do cliente SSH (ex: SSH-2.0-libssh_0.9.6). Impressao digital da ferramenta do atacante.';


-- ---------------------------------------------------------------------------
--  credencial - dicionario de pares usuario/senha
--
--  DECISAO DE MODELAGEM (documentar no README):
--  Milhoes de tentativas reutilizam poucos milhares de pares distintos.
--  Guardar usuario/senha em texto dentro de `tentativa` desperdica espaco e
--  torna "top 20 senhas" um GROUP BY sobre a tabela inteira. Normalizando,
--  `tentativa` guarda um BIGINT e o ranking sai de uma tabela pequena.
-- ---------------------------------------------------------------------------

CREATE TABLE credencial (
    id          BIGSERIAL PRIMARY KEY,
    usuario     TEXT NOT NULL,
    senha       TEXT NOT NULL,

    -- Chave natural composta: o par e o que identifica a credencial.
    CONSTRAINT credencial_par_unico
        UNIQUE (usuario, senha),

    -- Senha vazia e dado legitimo (bot testa senha em branco);
    -- usuario vazio nao e.
    CONSTRAINT credencial_usuario_nao_vazio
        CHECK (length(usuario) > 0),

    -- Trava de sanidade contra log malformado inflando a tabela.
    CONSTRAINT credencial_tamanho_razoavel
        CHECK (length(usuario) <= 256 AND length(senha) <= 256)
);


-- ---------------------------------------------------------------------------
--  tentativa - cada tentativa de autenticacao
--
--  A tabela que mais cresce. Deliberadamente estreita: 4 colunas uteis.
-- ---------------------------------------------------------------------------

CREATE TABLE tentativa (
    id              BIGSERIAL   PRIMARY KEY,
    sessao_id       BIGINT      NOT NULL,
    credencial_id   BIGINT      NOT NULL,
    sucesso         BOOLEAN     NOT NULL,
    ocorrido_em     TIMESTAMPTZ NOT NULL,

    CONSTRAINT tentativa_sessao_fk
        FOREIGN KEY (sessao_id) REFERENCES sessao (id)
        ON DELETE CASCADE,

    -- RESTRICT: credencial nao deve sumir enquanto houver tentativa apontando
    -- pra ela. Diferente de sessao, que cascateia.
    CONSTRAINT tentativa_credencial_fk
        FOREIGN KEY (credencial_id) REFERENCES credencial (id)
        ON DELETE RESTRICT,

    -- Chave natural do evento. Sem ela, reprocessar um log que cresceu
    -- duplica todas as tentativas das sessoes ja ingeridas - bug real,
    -- medido (5.916 -> 11.832 linhas). Ver sql/05_correcao_idempotencia.sql.
    -- Unica na pratica: o Cowrie carimba microssegundos.
    CONSTRAINT tentativa_evento_unico
        UNIQUE (sessao_id, credencial_id, ocorrido_em)
);


-- ---------------------------------------------------------------------------
--  comando - o que o atacante digitou depois de "entrar"
--
--  A parte mais interessante do dataset. O Cowrie finge aceitar o login,
--  entao o bot executa seu playbook inteiro achando que invadiu.
--
--  `ordem` preserva a sequencia. UNIQUE (sessao_id, ordem) garante que nao
--  existam dois "quinto comando" na mesma sessao - sem isso a reconstrucao
--  do playbook fica ambigua.
-- ---------------------------------------------------------------------------

CREATE TABLE comando (
    id              BIGSERIAL   PRIMARY KEY,
    sessao_id       BIGINT      NOT NULL,
    ordem           INTEGER     NOT NULL,
    comando         TEXT        NOT NULL,
    ocorrido_em     TIMESTAMPTZ NOT NULL,

    CONSTRAINT comando_sessao_fk
        FOREIGN KEY (sessao_id) REFERENCES sessao (id)
        ON DELETE CASCADE,

    CONSTRAINT comando_sequencia_unica
        UNIQUE (sessao_id, ordem),

    CONSTRAINT comando_ordem_positiva
        CHECK (ordem > 0),

    CONSTRAINT comando_nao_vazio
        CHECK (length(comando) > 0)
);


-- ---------------------------------------------------------------------------
--  artefato - arquivos que o atacante tentou baixar
--
--  Bots quase sempre rodam `wget http://.../bot.sh`. O Cowrie registra o
--  hash. Aqui guarda-se SO metadado (URL, hash, tamanho), nunca o conteudo,
--  e nada e executado.
-- ---------------------------------------------------------------------------

CREATE TABLE artefato (
    id              BIGSERIAL   PRIMARY KEY,
    sessao_id       BIGINT      NOT NULL,
    url             TEXT,
    sha256          CHAR(64)    NOT NULL,
    tamanho_bytes   BIGINT,
    ocorrido_em     TIMESTAMPTZ NOT NULL,

    CONSTRAINT artefato_sessao_fk
        FOREIGN KEY (sessao_id) REFERENCES sessao (id)
        ON DELETE CASCADE,

    -- Formato do hash validado pelo banco: 64 chars hex minusculos.
    CONSTRAINT artefato_sha256_formato
        CHECK (sha256 ~ '^[a-f0-9]{64}$'),

    CONSTRAINT artefato_tamanho_valido
        CHECK (tamanho_bytes IS NULL OR tamanho_bytes >= 0),

    -- Mesma logica de tentativa_evento_unico: chave natural do evento.
    CONSTRAINT artefato_evento_unico
        UNIQUE (sessao_id, sha256, ocorrido_em)
);

COMMENT ON TABLE artefato IS 'Metadados de downloads tentados. Somente hash e URL - nenhum binario e armazenado.';


-- ---------------------------------------------------------------------------
--  regra_deteccao - catalogo das regras
--
--  As regras viram LINHAS, nao codigo espalhado. Isso permite ligar alerta
--  -> regra por FK, ligar/desligar regra sem deploy, e versionar o catalogo.
-- ---------------------------------------------------------------------------

CREATE TABLE regra_deteccao (
    id              SMALLSERIAL PRIMARY KEY,
    codigo          TEXT        NOT NULL,
    nome            TEXT        NOT NULL,
    descricao       TEXT        NOT NULL,
    mitre_tecnica   TEXT,
    severidade      severidade_alerta NOT NULL,
    ativa           BOOLEAN     NOT NULL DEFAULT TRUE,
    criado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT regra_codigo_unico
        UNIQUE (codigo),

    -- Codigo em SCREAMING_SNAKE_CASE, referenciavel no codigo Python.
    CONSTRAINT regra_codigo_formato
        CHECK (codigo ~ '^[A-Z][A-Z0-9_]{2,49}$'),

    -- Formato MITRE ATT&CK: T1110 ou T1110.001 (subtecnica).
    CONSTRAINT regra_mitre_formato
        CHECK (mitre_tecnica IS NULL OR mitre_tecnica ~ '^T[0-9]{4}(\.[0-9]{3})?$')
);

COMMENT ON COLUMN regra_deteccao.mitre_tecnica IS 'ID da tecnica no MITRE ATT&CK. Vocabulario padrao da industria.';


-- ---------------------------------------------------------------------------
--  alerta - disparos das regras
--
--  A UNIQUE composta (regra, origem, janela_inicio) e o detalhe que faz o
--  sistema funcionar na pratica: sem ela, rodar as regras a cada 5 minutos
--  gera o mesmo alerta repetido pra sempre. Com ela, o INSERT usa
--  ON CONFLICT DO NOTHING e a deduplicacao fica garantida pelo banco -
--  nao por um `if` no Python que alguem esquece de manter.
-- ---------------------------------------------------------------------------

CREATE TABLE alerta (
    id              BIGSERIAL   PRIMARY KEY,
    regra_id        SMALLINT    NOT NULL,
    origem_id       BIGINT      NOT NULL,
    janela_inicio   TIMESTAMPTZ NOT NULL,
    janela_fim      TIMESTAMPTZ NOT NULL,
    detectado_em    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          status_alerta NOT NULL DEFAULT 'novo',

    -- JSONB porque cada regra produz evidencia de formato diferente
    -- (contagem, lista de comandos, hash...). Estruturar isso em colunas
    -- exigiria uma tabela por regra.
    evidencia       JSONB       NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT alerta_regra_fk
        FOREIGN KEY (regra_id) REFERENCES regra_deteccao (id)
        ON DELETE RESTRICT,

    CONSTRAINT alerta_origem_fk
        FOREIGN KEY (origem_id) REFERENCES origem (id)
        ON DELETE CASCADE,

    CONSTRAINT alerta_dedup
        UNIQUE (regra_id, origem_id, janela_inicio),

    CONSTRAINT alerta_janela_coerente
        CHECK (janela_fim > janela_inicio),

    CONSTRAINT alerta_evidencia_e_objeto
        CHECK (jsonb_typeof(evidencia) = 'object')
);


-- ---------------------------------------------------------------------------
--  arquivo_processado - controle de ingestao
--
--  Segunda camada de idempotencia, no nivel do arquivo. Antes de parsear,
--  o pipeline confere se aquele arquivo (por hash, nao por nome) ja entrou.
--  Hash e nao nome porque log rotacionado reaproveita nome.
-- ---------------------------------------------------------------------------

CREATE TABLE arquivo_processado (
    id                  BIGSERIAL   PRIMARY KEY,
    nome_arquivo        TEXT        NOT NULL,
    sha256              CHAR(64)    NOT NULL,
    linhas_lidas        INTEGER     NOT NULL,
    linhas_com_erro     INTEGER     NOT NULL DEFAULT 0,
    processado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT arquivo_sha256_unico
        UNIQUE (sha256),

    CONSTRAINT arquivo_sha256_formato
        CHECK (sha256 ~ '^[a-f0-9]{64}$'),

    CONSTRAINT arquivo_contagens_validas
        CHECK (linhas_lidas >= 0
           AND linhas_com_erro >= 0
           AND linhas_com_erro <= linhas_lidas)
);

COMMIT;
