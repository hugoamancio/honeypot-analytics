"""Renderiza as placas nos formatos que o LinkedIn exibe inteiros."""
import pathlib
from playwright.sync_api import sync_playwright

DOCS = pathlib.Path(r"C:\Users\hugoa\Desktop\claude\honeypot-analytics\docs")
PAGINA = DOCS / "composicao.html"
IMG = DOCS / "imagens"
IMG.mkdir(parents=True, exist_ok=True)

PLACAS = [
    ("#placa-paisagem", "post-paisagem.png", "1200x627"),
    ("#placa-retrato",  "post-retrato.png",  "1080x1350"),
]

with sync_playwright() as p:
    nav = p.chromium.launch()
    pag = nav.new_page(viewport={"width": 1360, "height": 2200},
                       device_scale_factor=2)
    pag.goto(PAGINA.as_uri())
    pag.emulate_media(color_scheme="dark")
    pag.wait_for_load_state("networkidle")
    pag.wait_for_timeout(2500)   # fontes do Google

    for sel, nome, medida in PLACAS:
        el = pag.locator(sel)
        el.scroll_into_view_if_needed()
        pag.wait_for_timeout(300)
        destino = IMG / nome
        el.screenshot(path=str(destino))
        cx = el.bounding_box()
        print(f"{nome:22} {medida:10} render {int(cx['width'])}x{int(cx['height'])}"
              f"  {destino.stat().st_size // 1024} KB")

    nav.close()
