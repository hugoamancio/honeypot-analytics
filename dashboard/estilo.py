"""
Camada de estilo do dashboard.

Isolada do app.py de proposito: CSS e um assunto, composicao de tela e outro.
Aqui moram os seletores do Streamlit, que sao a parte fragil - quando uma
versao nova renomeia uma classe, o conserto e neste arquivo e em nenhum outro.

Preferencia por seletores `data-testid`: sao contrato publico do Streamlit e
sobrevivem a upgrade. As classes `st-emotion-cache-*` sao geradas por hash e
mudam a cada release - usar uma delas e agendar uma quebra.
"""


def css(P):
    return f"""
<style>
  /* ---- Chrome do Streamlit ------------------------------------------
     Header, toolbar e badge "Deploy" sao ferramentas de desenvolvimento.
     Num painel que alguem vai abrir para OLHAR, eles so competem com o
     conteudo pela atencao.                                              */
  [data-testid="stHeader"],
  [data-testid="stToolbar"],
  [data-testid="stDecoration"],
  footer {{ display: none !important; }}

  /* ---- Superficie e largura ------------------------------------------
     O padrao do Streamlit trava o conteudo em ~970px. Num dashboard com
     graficos lado a lado isso desperdica meia tela e comprime os eixos.  */
  .stApp {{ background: {P['pagina']}; }}

  .block-container {{
      max-width: 1560px !important;
      padding: 2.2rem 2.4rem 4rem !important;
  }}

  [data-testid="stSidebar"] {{
      background: {P['surface']};
      border-right: 1px solid {P['borda']};
  }}

  /* ---- Tipografia ---------------------------------------------------- */
  html, body, [class*="css"] {{
      font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }}

  h1, h2, h3, h4 {{ color: {P['texto']} !important; }}

  /* ---- Cartao ---------------------------------------------------------
     Toda a moldura da tela sai daqui: os KPIs e os graficos usam a MESMA,
     senao os numeros ficam em caixa e os graficos flutuam soltos, o que le
     como duas telas diferentes coladas.

     COMO ISTO FUNCIONA, e por que nao e o obvio:

     O caminho natural seria estilizar o que `st.container(border=True)`
     produz. Nao da: nesta versao ele vira `stLayoutWrapper`, um testid
     generico compartilhado por 14 elementos da pagina, indistinguiveis
     entre si - nao ha como saber quais pediram borda.

     Entao a marcacao e NOSSA: cada cartao emite um `<span class="marca-
     cartao">` invisivel, e `:has()` estiliza o wrapper que o contem. O
     seletor passa a depender de algo que este projeto controla, e nao de
     um detalhe interno do Streamlit que muda entre releases.

     A segunda regra e o guarda de aninhamento: sem ela, cada wrapper
     ancestral tambem casaria com `:has(.marca-cartao)` e a tela ganharia
     molduras dentro de molduras. Ela zera todo wrapper que contenha OUTRO
     wrapper marcado, deixando so o mais interno.                          */
  .marca-cartao {{ display: none; }}

  [data-testid="stLayoutWrapper"]:has(.marca-cartao) {{
      background: {P['surface']};
      border: 1px solid {P['borda']};
      border-radius: 12px;
      padding: 16px 18px 8px;
  }}

  [data-testid="stLayoutWrapper"]:has([data-testid="stLayoutWrapper"] .marca-cartao) {{
      background: transparent;
      border: none;
      padding: 0;
  }}

  /* ---- Colunas: quebrar linha em vez de espremer -----------------------
     O Streamlit da as colunas `flex: 1 1 calc(20% - gap)` com
     `min-width: auto`. Resultado: com 5 colunas numa janela estreita elas
     encolhem indefinidamente em vez de quebrar. Medido a 810px de janela:
     43px por cartao, texto picado em quatro linhas, e cada um com uma
     altura diferente.

     `flex-wrap: wrap` ja vem do Streamlit, mas nunca dispara porque nada
     impede o encolhimento. O min-width e o gatilho que faltava: abaixo
     dele, a coluna desce para a linha seguinte.                          */
  [data-testid="stHorizontalBlock"] {{
      align-items: stretch;
  }}
  [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {{
      min-width: 186px;
  }}

  /* ---- KPI -------------------------------------------------------------
     Duas garantias diferentes, e as duas sao necessarias:

       min-height  = piso. Impede que um cartao de nota curta fique baixo
                     demais ao lado dos vizinhos.
       height 100% = teto comum. Faz todos os cartoes da fileira esticarem
                     ate o mais alto, entao a linha fica reta mesmo quando
                     uma nota quebra em duas linhas e outra nao.

     So o min-height nao basta: ele nivela por baixo, nao por cima.        */
  [data-testid="stColumn"] [data-testid="stLayoutWrapper"]:has(.marca-cartao) {{
      height: 100%;
  }}

  .kpi {{
      min-height: 116px;
      height: 100%;
      display: flex; flex-direction: column; justify-content: flex-start;
  }}
  .kpi .rotulo {{
      color: {P['mudo']}; font-size: 10.5px; font-weight: 600;
      text-transform: uppercase; letter-spacing: .07em;
      margin: 0 0 8px 0; white-space: nowrap;
  }}
  .kpi .valor {{
      color: {P['texto']}; font-size: 30px; font-weight: 650;
      line-height: 1; letter-spacing: -.02em;
      font-variant-numeric: tabular-nums;
  }}
  .kpi .nota {{
      color: {P['texto2']}; font-size: 11.5px; margin-top: 7px;
      line-height: 1.35;
  }}

  /* ---- Titulo de secao -------------------------------------------------
     Sobrancelha + titulo + contexto. A linha de contexto e o que separa
     "aqui esta um grafico" de "aqui esta o que este grafico quer dizer".  */
  .secao {{ margin: 30px 0 12px; }}
  .secao .olho {{
      color: {P['serie1']}; font-size: 10.5px; font-weight: 700;
      text-transform: uppercase; letter-spacing: .09em;
  }}
  .secao .titulo {{
      color: {P['texto']}; font-size: 20px; font-weight: 650;
      letter-spacing: -.01em; margin: 3px 0 0 0;
  }}
  .secao .contexto {{
      color: {P['texto2']}; font-size: 12.5px; margin: 5px 0 0 0;
      max-width: 78ch; line-height: 1.5;
  }}

  /* ---- Destaque -------------------------------------------------------- */
  .destaque {{
      background: {P['surface']};
      border: 1px solid {P['borda']};
      border-left: 3px solid {P['serie1']};
      border-radius: 10px;
      padding: 14px 18px;
      margin: 4px 0 8px;
  }}
  .destaque .numero {{
      color: {P['texto']}; font-size: 34px; font-weight: 650;
      line-height: 1; letter-spacing: -.02em;
      font-variant-numeric: tabular-nums;
  }}
  .destaque .texto {{
      color: {P['texto2']}; font-size: 12.5px; margin-top: 6px;
      line-height: 1.5;
  }}

  /* ---- Cabecalho de grafico -------------------------------------------
     Todo grafico ganha titulo e uma frase em linguagem simples, no MESMO
     formato. Antes a explicacao vivia ora no cabecalho da secao, ora numa
     legenda solta, e dois graficos nao tinham nenhuma - quem abrisse a tela
     sem conhecer o projeto olhava barras sem saber do que eram.

     A frase responde "o que estou vendo", nao "como foi calculado". Detalhe
     tecnico vai para o rodape do cartao.                                   */
  .gtitulo {{
      color: {P['texto']}; font-size: 17.5px; font-weight: 600;
      letter-spacing: -.01em; margin: 0 0 5px 0; line-height: 1.25;
  }}
  .gexplica {{
      color: {P['texto2']}; font-size: 13.5px; line-height: 1.55;
      margin: 0 0 16px 0; max-width: 72ch;
  }}
  .gexplica b {{ color: {P['texto']}; font-weight: 600; }}

  /* ---- Rodape de grafico: a ressalva tecnica, discreta ---------------- */
  .legenda {{
      color: {P['mudo']}; font-size: 11.5px; line-height: 1.5;
      margin: 10px 0 4px; max-width: 74ch;
      padding-top: 10px; border-top: 1px solid {P['borda']};
  }}
  .legenda b {{ color: {P['texto2']}; }}

  /* ---- Chips de severidade --------------------------------------------
     Cor + icone + rotulo, sempre os tres. Nenhum estado e comunicado so
     por cor: no tema claro 'media' e 'alta' ficam abaixo de 3:1 de
     contraste por construcao, e o par icone+texto e a compensacao.       */
  .chip {{
      display: inline-flex; align-items: center; gap: 6px;
      font-size: 11px; font-weight: 600; padding: 3px 9px;
      border-radius: 999px; margin-right: 6px;
      border: 1px solid {P['borda']};
      color: {P['texto2']};
  }}
  .chip .ponto {{
      width: 8px; height: 8px; border-radius: 50%; display: inline-block;
  }}

  /* Tabela: respira melhor e o cabecalho para de brigar com o dado. */
  [data-testid="stDataFrame"] {{ border-radius: 8px; }}
</style>
"""
