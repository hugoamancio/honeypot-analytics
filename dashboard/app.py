"""
Honeypot Analytics - dashboard.

PRINCIPIO DE DESENHO
    Esta camada NAO faz analise. Toda agregacao vive em view no PostgreSQL;
    aqui so ha `SELECT * FROM vw_...` e desenho. Consequencia pratica: a
    logica fica versionada em git, testavel no psql e reaproveitavel por uma
    API futura, sem nada reescrito.

    Se voce se pegar escrevendo GROUP BY em pandas neste arquivo, a conta
    esta no lugar errado - crie uma view.

    O CSS mora em estilo.py; a paleta, em paleta.py. Este arquivo so compoe.

USO
    streamlit run app.py
"""

import os
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address

import altair as alt
import pandas as pd
import psycopg
import streamlit as st

from estilo import css
from paleta import ICONE_SEVERIDADE, ORDEM_SEVERIDADE, SEVERIDADE, tema

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://analista:trocar_em_producao@localhost:5432/honeypot")

st.set_page_config(page_title="Honeypot Analytics", page_icon="🍯",
                   layout="wide", initial_sidebar_state="expanded")


# ===========================================================================
#  Dados
# ===========================================================================

@st.cache_resource
def conectar():
    """cache_resource: uma conexao para toda a sessao, nao uma por rerun."""
    return psycopg.connect(DATABASE_URL, autocommit=True)


@st.cache_data(ttl=60)
def consultar(sql):
    """
    cache_data com ttl de 60s: o Streamlit re-executa o script inteiro a cada
    interacao. Sem cache, mexer num filtro dispararia todas as queries de novo.

    A NORMALIZACAO DE TIPOS ABAIXO NAO E OPCIONAL.

    O psycopg mapeia tipos do Postgres para tipos ricos do Python:
        NUMERIC -> decimal.Decimal
        INET    -> ipaddress.IPv4Address

    Ambos viram coluna `object` no pandas. O Vega-Lite entao recebe algo que
    nao e numero num canal quantitativo, e o eixo sai com escala errada -
    grafico que renderiza sem erro nenhum e mostra a coisa errada, que e o
    pior tipo de defeito. Foi assim que a latencia apareceu num eixo de 0 a 22
    tendo maximo real de 0,35.

    Converter aqui, uma vez, em vez de em cada chamada: qualquer view nova
    ja nasce com o tratamento certo.
    """
    conn = conectar()
    with conn.cursor() as cur:
        cur.execute(sql)
        colunas = [d[0] for d in cur.description]
        df = pd.DataFrame(cur.fetchall(), columns=colunas)

    for col in df.columns:
        if df[col].dtype != "object" or df[col].empty:
            continue
        amostra = df[col].dropna()
        if amostra.empty:
            continue
        primeiro = amostra.iloc[0]
        if isinstance(primeiro, Decimal):
            df[col] = pd.to_numeric(df[col], errors="coerce")
        elif isinstance(primeiro, (IPv4Address, IPv6Address)):
            df[col] = df[col].astype(str)

    return df


def milhar(n):
    """12345 -> '12.345' (separador brasileiro)."""
    return f"{int(n):,}".replace(",", ".")


# ===========================================================================
#  Componentes de tela
# ===========================================================================

def cartao():
    """
    Marca o container atual como cartao.

    Emite um sentinela invisivel que o CSS encontra via :has(). Ver a
    explicacao longa em estilo.py - resumo: o testid que o Streamlit da ao
    container com borda e generico demais para servir de seletor, entao a
    marcacao passa a ser nossa.

    Uso:
        with st.container():
            cartao()
            ...conteudo...
    """
    st.markdown('<span class="marca-cartao"></span>', unsafe_allow_html=True)


def secao(olho, titulo, contexto=""):
    st.markdown(
        f"""<div class="secao">
              <div class="olho">{olho}</div>
              <p class="titulo">{titulo}</p>
              {f'<p class="contexto">{contexto}</p>' if contexto else ''}
            </div>""",
        unsafe_allow_html=True)


def kpi(rotulo, valor, nota="", cor=None):
    estilo = f"color:{cor};" if cor else ""
    st.markdown(
        f"""<div class="kpi">
              <p class="rotulo">{rotulo}</p>
              <div class="valor" style="{estilo}">{valor}</div>
              <div class="nota">{nota}</div>
            </div>""",
        unsafe_allow_html=True)


def legenda(texto):
    st.markdown(f'<p class="legenda">{texto}</p>', unsafe_allow_html=True)


def estilizar(chart, P, altura=260):
    """
    Enxoval comum a todo grafico: grade discreta, eixo apagado, fundo
    transparente. O dado e o unico elemento com cor forte na tela.
    """
    return (chart
            .properties(height=altura)
            .configure_view(strokeWidth=0, fill=None)
            .configure_axis(
                grid=True, gridColor=P["grade"], gridWidth=1,
                domainColor=P["eixo"], tickColor=P["eixo"],
                labelColor=P["mudo"], titleColor=P["texto2"],
                labelFontSize=11, titleFontSize=11, titlePadding=10,
                # 0 = sem truncamento. O padrao do Vega corta em 180px e
                # transforma BRUTE_FORCE_SSH em "BRUTE_FORCE_...", ilegivel
                # justamente nos rotulos que mais importam.
                labelLimit=0, titleFontWeight="normal")
            .configure_legend(
                labelColor=P["texto2"], titleColor=P["mudo"],
                labelFontSize=11, titleFontSize=10, symbolType="square",
                symbolSize=90, titlePadding=6, offset=8)
            .configure_axisY(grid=True, domain=False, ticks=False, labelPadding=6)
            .configure_axisX(grid=False))


def barras_magnitude(df, valor, rotulo, P, titulo_x, formato=",d"):
    """
    Barra horizontal com cor sequencial de uma unica matiz.

    Horizontal porque os rotulos sao longos (senhas, codigos de regra) - na
    vertical virariam texto rotacionado. cornerRadiusEnd arredonda so a ponta
    do dado; a base fica reta, ancorada na linha zero.

    O formato padrao e ",d" e nao ",": no d3-format a virgula sozinha nao
    especifica tipo e cai no formato geral, que usa exponencial acima de 100 -
    o eixo saia com "1e+2, 1.5e+2, 2e+2" no lugar de "100, 150, 200".
    """
    return alt.Chart(df).mark_bar(
        cornerRadiusEnd=4,
        height={"band": 0.72},        # respiro entre barras
    ).encode(
        x=alt.X(f"{valor}:Q", title=titulo_x, axis=alt.Axis(format=formato)),
        y=alt.Y(f"{rotulo}:N", sort="-x", title=None),
        color=alt.Color(f"{valor}:Q", scale=alt.Scale(range=P["rampa"]),
                        legend=None),
        tooltip=[alt.Tooltip(f"{rotulo}:N", title="item"),
                 alt.Tooltip(f"{valor}:Q", title="total", format=",")],
    )


# ===========================================================================
#  Barra lateral
# ===========================================================================

with st.sidebar:
    st.markdown("### 🍯 Honeypot Analytics")
    st.caption("Sensor `honeypot-udi-01`")
    st.markdown("---")
    escuro = st.toggle("Tema escuro", value=True)
    if st.button("Recarregar dados", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

P = tema(escuro)
st.markdown(css(P), unsafe_allow_html=True)

with st.sidebar:
    st.markdown("---")
    st.markdown("**Severidade**")
    for s in reversed(ORDEM_SEVERIDADE):
        st.markdown(
            f'<span class="chip">'
            f'<span class="ponto" style="background:{SEVERIDADE[s]}"></span>'
            f'{ICONE_SEVERIDADE[s]} {s}</span>',
            unsafe_allow_html=True)


# ===========================================================================
#  Cabecalho + KPIs
# ===========================================================================

resumo = consultar("SELECT * FROM vw_resumo").iloc[0]
dias = max(1, (resumo["coleta_ate"] - resumo["coleta_desde"]).days)

st.markdown(
    f"""<h1 style="margin:0;font-size:32px;font-weight:680;letter-spacing:-.025em;">
          Honeypot Analytics
        </h1>
        <p style="color:{P['mudo']};font-size:13px;margin:6px 0 22px;">
          {resumo['coleta_desde']:%d/%m/%Y} — {resumo['coleta_ate']:%d/%m/%Y}
          &nbsp;·&nbsp; {dias} dias de coleta
          &nbsp;·&nbsp; {resumo['ips']} IPs distintos
        </p>""",
    unsafe_allow_html=True)

colunas = st.columns(5, gap="small")
metricas = [
    ("Tentativas de login", milhar(resumo["tentativas"]),
     f"~{milhar(resumo['tentativas'] // dias)} por dia", None),
    ("Sessoes", milhar(resumo["sessoes"]),
     f"{milhar(resumo['ips'])} IPs distintos", None),
    ("Autenticaram", milhar(resumo["autenticadas"]),
     f"{milhar(resumo['comandos'])} comandos executados", None),
    ("Alertas abertos", milhar(resumo["alertas_abertos"]),
     "na fila de triagem", None),
    ("Criticos", milhar(resumo["alertas_criticos"]),
     "exigem acao imediata", SEVERIDADE["critica"]),
]
for col, (rot, val, nota, cor) in zip(colunas, metricas):
    with col, st.container():
        cartao()
        kpi(rot, val, nota, cor)


# ===========================================================================
#  Atividade
# ===========================================================================

secao("Volume", "Atividade ao longo do tempo",
      "Duas series porque SSH e Telnet sao alvos distintos: Telnet delata "
      "botnet de IoT, que varre porta 23 procurando camera e roteador.")

ativ = consultar("""
    SELECT hora, protocolo::text AS protocolo, sessoes, tentativas
    FROM vw_atividade_horaria ORDER BY hora
""")

if not ativ.empty:
    with st.container():
        cartao()
        linha = alt.Chart(ativ).mark_line(
            strokeWidth=2, interpolate="monotone",
        ).encode(
            x=alt.X("hora:T", title=None,
                    axis=alt.Axis(format="%d/%m", tickCount=12)),
            y=alt.Y("tentativas:Q", title="Tentativas por hora"),
            color=alt.Color("protocolo:N", title="PROTOCOLO",
                            scale=alt.Scale(domain=["ssh", "telnet"],
                                            range=[P["serie1"], P["serie2"]])),
            tooltip=[alt.Tooltip("hora:T", title="hora", format="%d/%m %H:%M"),
                     alt.Tooltip("protocolo:N", title="protocolo"),
                     alt.Tooltip("tentativas:Q", title="tentativas", format=","),
                     alt.Tooltip("sessoes:Q", title="sessoes")],
        )
        st.altair_chart(estilizar(linha, P, 250), use_container_width=True)


# ===========================================================================
#  Credenciais
# ===========================================================================

conc = consultar("""
    SELECT posicao, senha, pct_acumulado
    FROM vw_concentracao_senhas WHERE posicao <= 30
""")
dez = conc[conc["posicao"] == 10]
pct10 = float(dez.iloc[0]["pct_acumulado"]) if not dez.empty else None

# O denominador importa e nao pode ficar de fora: "10 senhas cobrem 83%" soa
# muito diferente se o universo tem 24 senhas ou 40 mil. Enquanto a fonte for
# o gerador sintetico, o universo e pequeno por construcao e a concentracao
# sai inflada. Mostrar o total distinto deixa o leitor calibrar sozinho.
universo = int(consultar(
    "SELECT COUNT(DISTINCT senha) AS n FROM credencial").iloc[0]["n"])

secao("Credenciais", "O dicionario dos atacantes",
      "A curva a direita e o achado pratico do painel: mede quantas senhas "
      "distintas bastam para cobrir a maior parte do trafego de ataque.")

if pct10 is not None:
    st.markdown(
        f"""<div class="destaque">
              <div class="numero">{pct10:.1f}%</div>
              <div class="texto">
                de <b>todas</b> as {milhar(resumo['tentativas'])} tentativas usaram
                apenas <b>10 senhas</b>, de {universo} distintas no total.
                Uma politica que barre esse punhado elimina a maior parte do
                trafego de ataque — sem firewall, sem WAF, sem custo.
                <br><span style="color:{P['mudo']};font-size:11.5px;">
                Ressalva: o dicionario do gerador sintetico tem so {universo}
                senhas, entao a concentracao aqui sai inflada. Com o sensor
                real — onde aparecem milhares de senhas distintas — o numero
                cai, e precisa ser medido de novo.
                </span>
              </div>
            </div>""",
        unsafe_allow_html=True)

e, d = st.columns(2, gap="medium")

with e, st.container():

    cartao()
    legenda("Pares <b>usuario / senha</b> mais tentados. "
            "<b>root</b> domina porque e o unico usuario que existe em "
            "praticamente todo Linux — o bot nao precisa adivinhar o nome.")
    cred = consultar("""
        SELECT usuario || ' / ' || COALESCE(NULLIF(senha, ''), '(vazia)') AS par,
               tentativas
        FROM vw_top_credenciais LIMIT 12
    """)
    st.altair_chart(
        estilizar(barras_magnitude(cred, "tentativas", "par", P, "Tentativas"),
                  P, 330),
        use_container_width=True)

with d, st.container():

    cartao()
    legenda("Curva de cobertura acumulada. Quanto mais rapido ela sobe, "
            "mais concentrado — e mais facil de bloquear — e o ataque.")
    if not conc.empty:
        # Uma serie so: sem caixa de legenda, o titulo do eixo ja identifica.
        area = alt.Chart(conc).mark_area(
            line={"color": P["serie1"], "strokeWidth": 2},
            color=alt.Gradient(
                gradient="linear",
                stops=[alt.GradientStop(color=P["surface"], offset=0),
                       alt.GradientStop(color=P["serie1"], offset=1)],
                x1=1, x2=1, y1=1, y2=0),
            opacity=0.3,
        ).encode(
            x=alt.X("posicao:Q", title="As N senhas mais tentadas",
                    scale=alt.Scale(nice=False, domainMin=1)),
            y=alt.Y("pct_acumulado:Q", title="% das tentativas cobertas",
                    scale=alt.Scale(domain=[0, 100])),
            tooltip=[alt.Tooltip("posicao:Q", title="top N"),
                     alt.Tooltip("senha:N", title="senha nesta posicao"),
                     alt.Tooltip("pct_acumulado:Q", title="% acumulado",
                                 format=".1f")],
        )
        st.altair_chart(estilizar(area, P, 330), use_container_width=True)


# ===========================================================================
#  Deteccao
# ===========================================================================

regras = consultar("""
    SELECT codigo, COALESCE(mitre_tecnica, '—') AS mitre,
           severidade::text AS severidade, alertas, ips_envolvidos
    FROM vw_alertas_por_regra ORDER BY alertas DESC
""")

secao("Deteccao", "Regras e disparos",
      "Cada regra e uma query SQL mapeada para uma tecnica do MITRE ATT&CK, "
      "o vocabulario padrao da industria para descrever comportamento de "
      "atacante. Cor de severidade sempre acompanhada de icone e rotulo.")

if not regras.empty:
    regras["rotulo"] = (regras["severidade"].map(ICONE_SEVERIDADE) + "  "
                        + regras["codigo"] + "   " + regras["mitre"])

    with st.container():

        cartao()
        barras = alt.Chart(regras).mark_bar(
            cornerRadiusEnd=4, height={"band": 0.7},
        ).encode(
            x=alt.X("alertas:Q", title="Alertas gerados"),
            y=alt.Y("rotulo:N", sort="-x", title=None),
            # Paleta de status, nunca a categorica: severidade nao e
            # "mais uma serie" e nao pode se confundir com uma.
            color=alt.Color("severidade:N", title="SEVERIDADE",
                            scale=alt.Scale(
                                domain=ORDEM_SEVERIDADE,
                                range=[SEVERIDADE[s] for s in ORDEM_SEVERIDADE]),
                            sort=ORDEM_SEVERIDADE),
            tooltip=[alt.Tooltip("codigo:N", title="regra"),
                     alt.Tooltip("mitre:N", title="MITRE ATT&CK"),
                     alt.Tooltip("severidade:N", title="severidade"),
                     alt.Tooltip("alertas:Q", title="alertas", format=","),
                     alt.Tooltip("ips_envolvidos:Q", title="IPs")],
        )
        st.altair_chart(estilizar(barras, P, 350), use_container_width=True)

    mudas = regras[regras["alertas"] == 0]
    if not mudas.empty:
        st.warning(
            "Sem nenhum disparo: **" + ", ".join(mudas["codigo"]) + "**. "
            "Regra silenciosa e indistinguivel de regra quebrada — confirme "
            "que os dados exercitam esse padrao antes de confiar nela.")


# ===========================================================================
#  Comportamento
# ===========================================================================

secao("Comportamento", "Origem e tempo de reacao",
      "A latencia a direita mede o intervalo entre autenticar e digitar o "
      "primeiro comando. E a evidencia mais direta de automacao no painel.")

e2, d2 = st.columns(2, gap="medium")

with e2, st.container():

    cartao()
    legenda("Sessoes por pais de origem. Pais e a metrica ingenua — o "
            "agrupamento por <b>ASN</b> (o provedor dono do bloco de rede) "
            "revela muito mais, e ja esta em <code>vw_infra_atacante</code>.")
    paises = consultar("""
        SELECT pais, SUM(sessoes)::int AS sessoes
        FROM vw_infra_atacante WHERE pais IS NOT NULL
        GROUP BY pais ORDER BY sessoes DESC LIMIT 12
    """)
    st.altair_chart(
        estilizar(barras_magnitude(paises, "sessoes", "pais", P, "Sessoes"),
                  P, 310),
        use_container_width=True)

with d2, st.container():

    cartao()
    lat = consultar("""
        SELECT ip, pais, latencia_1o_comando AS segundos, roteiro
        FROM vw_playbook_inicial
        WHERE latencia_1o_comando IS NOT NULL
        ORDER BY latencia_1o_comando LIMIT 15
    """)
    # Estatistica da POPULACAO INTEIRA, nao das 15 linhas plotadas.
    # Calcular a mediana sobre o LIMIT 15 daria a mediana das mais rapidas
    # (0,16s) e a legenda, colada embaixo do grafico, seria lida como se
    # fosse o numero global (0,47s). Mesma classe de erro do marco zero:
    # o valor esta certo, o que ele mede e que nao e o que o texto promete.
    lat_geral = consultar("""
        SELECT ROUND(MIN(latencia_1o_comando), 2) AS minimo,
               ROUND(percentile_cont(0.5) WITHIN GROUP
                     (ORDER BY latencia_1o_comando)::numeric, 2) AS mediana,
               ROUND(MAX(latencia_1o_comando), 2) AS maximo,
               COUNT(*) AS n
        FROM vw_playbook_inicial WHERE latencia_1o_comando IS NOT NULL
    """).iloc[0]
    if not lat.empty:
        # Numeros calculados, nunca escritos a mao: legenda com valor fixo
        # envelhece em silencio assim que o dado muda.
        legenda(
            f"As <b>15 sessoes mais rapidas</b>. Marco zero = instante da "
            f"<b>autenticacao</b>, nao da conexao. Nas "
            f"<b>{int(lat_geral['n'])}</b> sessoes com comando, a mediana e "
            f"<b>{lat_geral['mediana']:.2f}s</b> e o maximo "
            f"<b>{lat_geral['maximo']:.2f}s</b> — nenhuma passa de um segundo. "
            f"Nenhum humano le a tela e digita nesse tempo.")
        pontos = alt.Chart(lat).mark_circle(
            size=120, opacity=0.9,
            stroke=P["surface"], strokeWidth=2,   # anel separa marcas sobrepostas
        ).encode(
            x=alt.X("segundos:Q", title="Segundos ate o primeiro comando",
                    axis=alt.Axis(format=".2f")),
            y=alt.Y("ip:N", sort="x", title=None),
            color=alt.value(P["serie1"]),
            tooltip=[alt.Tooltip("ip:N", title="IP"),
                     alt.Tooltip("pais:N", title="pais"),
                     alt.Tooltip("segundos:Q", title="latencia (s)", format=".2f"),
                     alt.Tooltip("roteiro:N", title="playbook")],
        )
        st.altair_chart(estilizar(pontos, P, 310), use_container_width=True)


# ===========================================================================
#  Fila de triagem
# ===========================================================================

secao("Triagem", "Fila de alertas abertos",
      "A tabela e tambem a via de acesso alternativa a cor: tudo que os "
      "graficos acima comunicam visualmente esta aqui em texto.")

fila = consultar("""
    SELECT severidade::text AS sev, regra, COALESCE(mitre_tecnica,'—') AS mitre,
           host(ip) AS ip, pais, janela_inicio, evidencia::text AS evidencia
    FROM vw_alertas_abertos LIMIT 200
""")

if not fila.empty:
    fila.insert(0, "sinal", fila["sev"].map(ICONE_SEVERIDADE))
    st.dataframe(
        fila, use_container_width=True, hide_index=True, height=360,
        column_config={
            "sinal": st.column_config.TextColumn("", width="small"),
            "sev": st.column_config.TextColumn("Severidade", width="small"),
            "regra": st.column_config.TextColumn("Regra", width="medium"),
            "mitre": st.column_config.TextColumn("MITRE", width="small"),
            "ip": st.column_config.TextColumn("IP", width="small"),
            "pais": st.column_config.TextColumn("Pais", width="small"),
            "janela_inicio": st.column_config.DatetimeColumn(
                "Janela", format="DD/MM/YYYY HH:mm"),
            "evidencia": st.column_config.TextColumn("Evidencia", width="large"),
        })
    st.caption(f"{len(fila)} de {milhar(resumo['alertas_abertos'])} alertas abertos.")
