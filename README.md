# Honeypot Analytics

Um mini-SIEM sobre honeypot SSH: coleta tentativas de invasão, guarda num
PostgreSQL modelado, aplica 11 regras de detecção escritas em SQL e apresenta
a fila de alertas num dashboard.

`PostgreSQL 16` · `Python 3.13` · `Streamlit` · `Docker`

---

## ⚠️ Estado atual dos dados

**Os dados deste repositório são sintéticos.** São produzidos por
[`gerador/gerar_logs.py`](gerador/gerar_logs.py), que emite eventos no formato
exato do [Cowrie](https://github.com/cowrie/cowrie). O sensor real ainda não
está no ar.

Isso é uma decisão de projeto, não uma pendência esquecida: desenvolver contra
o gerador permitiu terminar modelo, pipeline, regras e dashboard **sem ficar
bloqueado esperando infraestrutura**. Quando o honeypot real entrar, o parser é
o mesmo — nenhuma linha de código muda, só o caminho do arquivo.

Todo número abaixo vem dos dados sintéticos e será **remedido** com tráfego
real. Onde a origem sintética distorce a conclusão, está dito explicitamente.

---

## O que é um honeypot

Um servidor isca. Ele finge ser um SSH mal configurado e fica exposto na
internet. Bots varrem a rede 24h procurando servidor frágil; quando acham este,
tentam invadir — e cada tentativa é registrada.

O Cowrie vai além: ele **finge aceitar o login**. O atacante acha que entrou e
executa seu roteiro inteiro dentro de um ambiente falso, que grava tudo. É daí
que sai a parte mais interessante do dataset: o que o bot faz nos primeiros
segundos depois de "invadir".

É uma postura **defensiva**. O servidor é próprio, nada é atacado, e só se
observa quem chega por conta própria.

---

## O que os dados mostram

| Métrica | Valor |
|---|---|
| Sessões | 1.500 |
| Tentativas de login | 11.923 |
| IPs distintos | 390 |
| Sessões que autenticaram | 38 |
| Alertas gerados | 314 (66 críticos) |
| Período | 11–25/08/2026 |

### As senhas se concentram brutalmente

10 senhas cobrem **82,9%** de todas as tentativas; 5 cobrem 60%; 20 cobrem 98%.

> **Ressalva honesta:** o dicionário do gerador tem apenas 24 senhas distintas,
> então essa concentração está inflada por construção. Num honeypot real
> aparecem milhares de senhas e a cobertura cai. O formato do achado se
> mantém — a cauda é sempre longa e a cabeça sempre curta — mas **o número
> precisa ser medido de novo** com dado real antes de ser citado.

### Bot não hesita

Latência entre autenticar e digitar o primeiro comando, nas 38 sessões com
atividade:

| mínimo | mediana | máximo |
|---|---|---|
| 0,09 s | 0,47 s | 0,88 s |

Nenhuma passa de um segundo. Um operador humano leria a tela antes de digitar.
Essa coluna sozinha separa automação de pessoa.

### Cadência revela agendamento

Um IP abriu 80 sessões espaçadas em exatamente 30 minutos, com coeficiente de
variação de **0,0082**. Isso não é alguém tentando invadir — é um `cron`
apontado para o alvo. A regra `HORARIO_REGULAR` detecta isso sem olhar o
conteúdo de nada, só a estatística dos intervalos.

---

## Arquitetura

```
   honeypot (Cowrie)              ← ainda não implantado
   gerador/gerar_logs.py          ← substituto atual, mesmo formato
              │
              ▼   cowrie.json  (um JSON por linha)
   pipeline/ingest.py             parse · normaliza · UPSERT
              │
              ▼
   ┌──────────────────────────────────────────┐
   │  PostgreSQL                              │
   │  9 tabelas · 43 constraints · 30 índices │
   │  19 views (5 análise + 3 apoio + 11 regras) │
   └──────────────────────────────────────────┘
              │                        │
              ▼                        ▼
   pipeline/detectar.py         dashboard/app.py
   grava em `alerta`            lê só de views
```

**A inteligência mora no banco.** As regras são views, as análises são views. O
Python só move dados. Isso mantém a lógica versionada em git, testável no
`psql` e reaproveitável por uma API futura sem reescrever nada.

---

## Decisões de modelagem

### Credenciais normalizadas

Milhões de tentativas reutilizam poucos milhares de pares usuário/senha.
Guardá-los como texto em `tentativa` desperdiçaria espaço e tornaria "top 20
senhas" um `GROUP BY` sobre a tabela inteira. Com `credencial` própria,
`tentativa` guarda um `BIGINT` e o ranking sai de uma tabela pequena.

### Índices escolhidos por carga, não por reflexo

O principal é `(sessao_id, ocorrido_em)` — **nessa ordem**. Toda regra pergunta
"o que a sessão X fez entre A e B": filtra sessão por igualdade e tempo por
intervalo. Um índice B-tree só usa a segunda coluna depois de fixar a primeira,
então a igualdade vem primeiro. Invertido, o banco varreria toda a janela de
tempo antes de filtrar a sessão.

Nenhum índice entra sem justificativa escrita em
[`02_indices.sql`](sql/02_indices.sql). Índice não é de graça: ocupa disco e
torna todo `INSERT` mais lento.

### Regras como linhas, não como código

Cada regra é uma **view** mais uma linha em `regra_deteccao`, com sua técnica
[MITRE ATT&CK](https://attack.mitre.org/). O executor
[`detectar.py`](pipeline/detectar.py) não contém **uma linha** de lógica de
detecção: lê o catálogo, monta o nome da view e faz `INSERT … SELECT`.

Consequências práticas: regra nova é uma view + uma linha. Desligar uma regra
em produção é `UPDATE regra_deteccao SET ativa = FALSE` — sem deploy.

### As 11 regras

| Código | MITRE | O que detecta |
|---|---|---|
| `CREDENCIAL_VALIDA_USADA` | T1078 | qualquer autenticação bem-sucedida |
| `DOWNLOAD_ARTEFATO` | T1105 | `wget`/`curl`/`tftp` trazendo payload |
| `PERSISTENCIA_SSH_KEY` | T1098.004 | escrita em `authorized_keys`, cron, `rc.local` |
| `DESATIVACAO_DEFESA` | T1562.001 | derruba firewall ou SELinux |
| `LIMPEZA_RASTRO` | T1070.003 | apaga histórico e log |
| `MINERACAO_CRIPTO` | T1496 | minerador ou pool de mineração |
| `PASSWORD_SPRAY` | T1110.003 | uma senha contra 10+ usuários |
| `BRUTE_FORCE_SSH` | T1110.001 | 20+ falhas em janela de 5 min |
| `RECON_SISTEMA` | T1082 | 3+ comandos de reconhecimento |
| `REINCIDENTE` | — | 5+ sessões do mesmo IP em 24 h |
| `HORARIO_REGULAR` | — | cadência estatisticamente regular |

`BRUTE_FORCE_SSH` usa **janela deslizante de verdade**
(`RANGE BETWEEN INTERVAL '5 minutes' PRECEDING`), não balde fixo: um ataque que
começa 23h59 e termina 00h01 seria partido em dois baldes e talvez nenhum
atingisse o limiar.

---

## Três bugs que valeram mais que o código

### 1. Idempotência que não segurava

O pipeline controlava duplicata por hash do arquivo. Reprocessar fez
`tentativa` saltar de **5.916 para 11.832 linhas**.

A causa não era o teste. O `cowrie.json` **cresce durante o dia**: o hash muda,
o arquivo passa pela checagem, as sessões antigas voltam no parse, `sessao` se
protege com `ON CONFLICT` e devolve o id existente — e então todas as
tentativas daquelas sessões são inseridas de novo. **Duplicaria em produção
todo dia, em silêncio.**

Corrigido com chave natural `(sessao_id, credencial_id, ocorrido_em)` e uma
migration que deduplicou as 5.916 linhas
([`05_correcao_idempotencia.sql`](sql/05_correcao_idempotencia.sql)). A garantia
passou a ser do banco, não da disciplina de quem chama.

### 2. Três regras que nunca disparavam

Na primeira execução, `PASSWORD_SPRAY`, `RECON_SISTEMA` e `HORARIO_REGULAR`
deram zero alerta. Nenhuma estava quebrada — o **gerador** é que não produzia
aqueles padrões:

- o dicionário tinha no máximo 2 usuários por senha, contra limiar de 10;
- o atacante com cadência fixa também recebia sessões aleatórias, o que
  destruía a regularidade (coeficiente de variação medido: 0,55; limiar: 0,15).

**Regra silenciosa é indistinguível de regra quebrada.** Hoje o dashboard avisa
na tela quando uma regra fica muda.

### 3. Uma métrica com o nome errado

A latência do atacante era calculada a partir do **início da sessão**. Entre a
conexão e o primeiro comando cabem todas as tentativas de senha que falharam —
numa sessão de 60 tentativas, uns 80 segundos. O gráfico mostrava até 300s onde
o real era menos de 1s, e a legenda dizia "entre o login e o primeiro comando".

O valor estava certo; o que ele media é que não era o que o nome prometia.
**Métrica com nome errado é pior que métrica ausente** — ela é citada com
confiança e desmorona na primeira pergunta.

Corrigido em [`08_correcao_latencia.sql`](sql/08_correcao_latencia.sql). A mesma
classe de erro reapareceu depois numa legenda que calculava a mediana sobre as
15 linhas plotadas em vez da população inteira (0,16 s contra 0,47 s reais);
também corrigida.

---

## Como rodar

Requisitos: Docker e Python 3.11+.

```bash
# 1. Banco (schema, índices, views e regras entram no primeiro start)
docker compose up -d

# 2. Dependências
pip install -r requirements.txt

# 3. Gerar dados sintéticos
python gerador/gerar_logs.py --sessoes 1500 --dias 14 --seed 7

# 4. Ingerir
python pipeline/ingest.py dados/cowrie.json

# 5. Rodar as regras
python pipeline/detectar.py

# 6. Dashboard
streamlit run dashboard/app.py
```

Dashboard em `http://localhost:8501`. Banco em `localhost:5432`
(`analista` / `honeypot`).

### Explorar direto no SQL

```bash
docker exec -it honeypot_db psql -U analista -d honeypot
```

```sql
SELECT * FROM vw_top_credenciais LIMIT 10;
SELECT * FROM vw_playbook_inicial ORDER BY latencia_1o_comando LIMIT 5;
SELECT * FROM vw_alertas_abertos WHERE severidade = 'critica';
```

---

## Estrutura

```
sql/
  01_schema.sql                  9 tabelas, 3 enums, 43 constraints
  02_indices.sql                 30 índices, cada um justificado
  03_views.sql                   views de análise
  04_seed_regras.sql             catálogo das 11 regras
  05_correcao_idempotencia.sql   migration — bug 1
  06_regras.sql                  as 11 regras, uma view cada
  07_views_dashboard.sql         agregações do painel
  08_correcao_latencia.sql       migration — bug 3
gerador/gerar_logs.py            eventos sintéticos no formato Cowrie
pipeline/ingest.py               ingestão idempotente em 2 camadas
pipeline/detectar.py             executor de regras (sem lógica de detecção)
dashboard/app.py                 composição da tela
dashboard/estilo.py              CSS isolado
dashboard/paleta.py              paleta validada para daltonismo
```

---

## Sobre as cores do dashboard

Nenhuma foi escolhida por gosto:

- **Categórica** (SSH × Telnet) — ordem fixa validada para daltonismo, usando
  só os dois slots de maior margem de separação.
- **Magnitude** — uma única matiz, do claro ao escuro. Nunca arco-íris: matiz
  não carrega ordem, luminosidade carrega.
- **Severidade** — paleta de status separada, nunca reaproveitada como série, e
  **sempre acompanhada de ícone e rótulo**: no tema claro dois níveis ficam
  abaixo de 3:1 de contraste, então a cor nunca é o único canal de informação.

---

## Próximos passos

- [ ] Implantar o Cowrie em VPS isolado e trocar a fonte de dados
- [ ] Enriquecimento por geoIP/ASN (colunas já existem, agora sempre nulas)
- [ ] Remedir a concentração de senhas com dados reais
- [ ] `EXPLAIN ANALYZE` antes/depois de cada índice, com dado em escala
- [ ] Particionamento de `tentativa` por tempo, quando justificar
