# ============================================================================
#  Traz o log do honeypot para a maquina local e ingere no banco.
#
#  Roda no SEU Windows, nao no servidor.
#
#  USO
#      .\coletar.ps1 -Ip 123.45.67.89 -Chave C:\caminho\chave.key
#
#  Depois de rodar uma vez, agende no Task Scheduler para repetir de hora em
#  hora. A ingestao e idempotente nas duas pontas, entao rodar demais nao
#  duplica nada - e rodar de menos so atrasa o dado.
# ============================================================================

param(
    [Parameter(Mandatory = $true)][string]$Ip,
    [Parameter(Mandatory = $true)][string]$Chave,
    [string]$Usuario = "ubuntu",
    [int]$PortaSsh = 2200,
    [switch]$SomenteBaixar
)

$ErrorActionPreference = "Stop"
$raiz    = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$destino = Join-Path $raiz "dados\cowrie.json"
$python  = "C:\Users\hugoa\AppData\Local\Programs\Python\Python313\python.exe"

if (-not (Test-Path $Chave)) { throw "Chave nao encontrada: $Chave" }

# ---------------------------------------------------------------------------
#  1. Baixar
#
#  A porta padrao aqui e 2200, nao 22: depois do deploy, a 22 pertence ao
#  honeypot. Conectar na 22 te levaria ao Cowrie - voce entraria no seu
#  proprio honeypot e veria um sistema falso, o que rende uma confusao
#  memoravel as 2 da manha.
# ---------------------------------------------------------------------------
Write-Host "==> Baixando o log de $Usuario@$Ip (porta $PortaSsh)..." -ForegroundColor Cyan

$remoto = "${Usuario}@${Ip}:~/cowrie/var/log/cowrie/cowrie.json"
& scp -i $Chave -P $PortaSsh -o StrictHostKeyChecking=accept-new $remoto $destino

if ($LASTEXITCODE -ne 0) { throw "scp falhou (codigo $LASTEXITCODE)" }

$tamanho = (Get-Item $destino).Length
$linhas  = (Get-Content $destino | Measure-Object -Line).Lines
Write-Host ("    {0:N0} linhas, {1:N1} MB" -f $linhas, ($tamanho / 1MB)) -ForegroundColor Green

if ($SomenteBaixar) { Write-Host "`n[-SomenteBaixar] parando aqui."; exit 0 }

# ---------------------------------------------------------------------------
#  2. Ingerir e detectar
# ---------------------------------------------------------------------------
Write-Host "`n==> Ingerindo no PostgreSQL..." -ForegroundColor Cyan
& $python (Join-Path $raiz "pipeline\ingest.py") $destino
if ($LASTEXITCODE -ne 0) { throw "ingest.py falhou" }

Write-Host "`n==> Rodando as regras de deteccao..." -ForegroundColor Cyan
& $python (Join-Path $raiz "pipeline\detectar.py")

Write-Host "`nPronto. Abra o dashboard:" -ForegroundColor Green
Write-Host "    streamlit run dashboard\app.py"
