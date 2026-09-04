"""
Grava uma passagem pelo dashboard.

REQUISITOS
    pip install playwright && playwright install chromium
    ffmpeg no PATH (winget install Gyan.FFmpeg)
    dashboard rodando em localhost:8501

USO
    python docs/gravar_video.py
    ffmpeg -ss 14 -i docs/imagens/dashboard.webm -c:v libx264 -crf 22 \
           -pix_fmt yuv420p -movflags +faststart -r 30 docs/imagens/dashboard.mp4

O Playwright grava em WebM; a conversao para MP4 e necessaria porque o
LinkedIn aceita MP4 de forma confiavel e WebM nem sempre.

O `-ss 14` NAO e chute: a gravacao comeca quando o contexto do navegador e
criado, ANTES do goto. Os primeiros ~14 segundos sao tela preta enquanto o
Streamlit carrega e o CSS que esconde a barra lateral e aplicado. Sem o
corte, o video comeca com meio minuto de nada.

Ritmo: pausa no topo, rolagem lenta, pausa em cada bloco. Video que rola
rapido nao deixa ler o texto explicativo dos graficos - que e justamente o
que da valor a tela.
"""
import pathlib, shutil
from playwright.sync_api import sync_playwright

SAIDA = pathlib.Path(r"C:\Users\hugoa\Desktop\claude\honeypot-analytics\docs\imagens")
TEMP = pathlib.Path(r"C:\Users\hugoa\AppData\Local\Temp\claude\C--Users-hugoa-Desktop-claude\ea299702-d15b-4940-8d35-1cfa99783d1c\scratchpad\video")
if TEMP.exists():
    shutil.rmtree(TEMP)
TEMP.mkdir(parents=True, exist_ok=True)

LARG, ALT = 1280, 720          # 16:9, dentro dos limites do LinkedIn

with sync_playwright() as p:
    nav = p.chromium.launch()
    ctx = nav.new_context(
        viewport={"width": LARG, "height": ALT},
        record_video_dir=str(TEMP),
        record_video_size={"width": LARG, "height": ALT},
    )
    pag = ctx.new_page()
    pag.emulate_media(color_scheme="dark")
    pag.goto("http://localhost:8501", wait_until="networkidle", timeout=90000)
    pag.wait_for_timeout(9000)      # Streamlit renderiza os graficos depois

    # Esconde a barra lateral: ela nao muda durante a rolagem e rouba
    # 1/4 da largura do quadro.
    pag.add_style_tag(content="""
        [data-testid="stSidebar"] { display: none !important; }
        .block-container { max-width: 100% !important; padding-top: 1.6rem !important; }
    """)
    pag.wait_for_timeout(2500)

    alvo = pag.evaluate("document.querySelector('section.stMain').scrollHeight")
    print(f"altura da pagina: {alvo}px")

    def rolar_ate(y, passos, espera=40):
        atual = pag.evaluate("document.querySelector('section.stMain').scrollTop")
        for i in range(1, passos + 1):
            pos = atual + (y - atual) * i / passos
            pag.evaluate(f"document.querySelector('section.stMain').scrollTop = {pos}")
            pag.wait_for_timeout(espera)

    pag.wait_for_timeout(2600)                      # respira no topo
    for destino, pausa in [(560, 1900), (1180, 1900), (1850, 1900),
                           (2560, 1900), (3250, 1900), (alvo, 2600)]:
        rolar_ate(destino, passos=34)
        pag.wait_for_timeout(pausa)

    caminho_video = pag.video.path()
    ctx.close()
    nav.close()

origem = pathlib.Path(caminho_video)
destino_webm = SAIDA / "dashboard.webm"
shutil.move(str(origem), str(destino_webm))
print(f"webm: {destino_webm.name}  {destino_webm.stat().st_size // 1024} KB")
