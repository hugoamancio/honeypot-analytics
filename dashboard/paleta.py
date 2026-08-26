"""
Paleta do projeto.

Um unico lugar define cor. Nenhum hex solto espalhado pelos graficos - trocar
o tema e editar este arquivo, nao cacar `#2a78d6` em cinco lugares.

As cores NAO foram escolhidas por gosto:

  - Categoricas seguem uma ordem fixa e validada para daltonismo. A ordem e o
    mecanismo de seguranca, nao enfeite: slots vizinhos precisam se separar sob
    simulacao de CVD. Usamos so os slots 1-2 (azul, laranja), que sao os de
    maior margem.
  - Magnitude usa UMA cor, do claro ao escuro. Nunca arco-iris: hue nao carrega
    ordem, luminosidade carrega.
  - Severidade usa uma paleta de status separada, que nunca e reaproveitada
    como "serie 3" - senao um alerta critico passa a parecer uma categoria.
    E sempre acompanha o rotulo textual: cor sozinha nunca carrega significado.
"""

CLARO = {
    "surface":   "#fcfcfb",
    "pagina":    "#f9f9f7",
    "texto":     "#0b0b0b",
    "texto2":    "#52514e",
    "mudo":      "#898781",
    "grade":     "#e1e0d9",
    "eixo":      "#c3c2b7",
    "borda":     "rgba(11,11,11,0.10)",
    "serie1":    "#2a78d6",   # azul
    "serie2":    "#eb6834",   # laranja
    # Rampa sequencial azul, claro -> escuro (magnitude)
    "rampa":     ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#2a78d6", "#256abf", "#184f95"],
}

ESCURO = {
    "surface":   "#1a1a19",
    "pagina":    "#0d0d0d",
    "texto":     "#ffffff",
    "texto2":    "#c3c2b7",
    "mudo":      "#898781",
    "grade":     "#2c2c2a",
    "eixo":      "#383835",
    "borda":     "rgba(255,255,255,0.10)",
    "serie1":    "#3987e5",
    "serie2":    "#d95926",
    "rampa":     ["#184f95", "#256abf", "#2a78d6", "#3987e5", "#6da7ec", "#9ec5f4", "#cde2fb"],
}

# Paleta de status: fixa, identica nos dois temas, reservada para severidade.
SEVERIDADE = {
    "baixa":   "#0ca30c",
    "media":   "#fab219",
    "alta":    "#ec835a",
    "critica": "#d03b3b",
}

# Ordem semantica, nao alfabetica - o eixo precisa sair do menos para o mais grave.
ORDEM_SEVERIDADE = ["baixa", "media", "alta", "critica"]

# Icone junto do rotulo: no tema claro, 'media' e 'alta' ficam abaixo de 3:1 de
# contraste por construcao. O par icone + texto e a compensacao prevista, e o
# que impede a cor de ser o unico canal de informacao.
ICONE_SEVERIDADE = {
    "baixa":   "●",
    "media":   "◆",
    "alta":    "▲",
    "critica": "⬣",
}


def tema(escuro=False):
    return ESCURO if escuro else CLARO
