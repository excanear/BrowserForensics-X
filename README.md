<div align="center">

<img src="docs/assets/hero.svg" alt="BrowserForensics-X — forense de navegadores com rigor probatório em um único arquivo Bash" width="100%">

<br>

<img alt="Bash 4.4+" src="https://img.shields.io/badge/bash-4.4%2B-22d3ee?style=flat-square&logo=gnubash&logoColor=white&labelColor=0b1222">
<img alt="Python 3.8+ stdlib" src="https://img.shields.io/badge/motor-python%203.8%2B%20stdlib-a78bfa?style=flat-square&logo=python&logoColor=white&labelColor=0b1222">
<img alt="Linux · Windows · macOS" src="https://img.shields.io/badge/plataformas-linux%20%C2%B7%20windows%20%C2%B7%20macOS-60a5fa?style=flat-square&labelColor=0b1222">
<img alt="selftest 160/160" src="https://img.shields.io/badge/selftest-160%2F160-34d399?style=flat-square&labelColor=0b1222">
<img alt="offline" src="https://img.shields.io/badge/rede-nunca-f472b6?style=flat-square&labelColor=0b1222">
<img alt="arquivo único" src="https://img.shields.io/badge/distribui%C3%A7%C3%A3o-um%20arquivo%20.sh-fbbf24?style=flat-square&labelColor=0b1222">

<h3>
  <a href="#inicio">Início rápido</a>
  <span>&nbsp;·&nbsp;</span>
  <a href="#cobertura">Cobertura</a>
  <span>&nbsp;·&nbsp;</span>
  <a href="#integridade">Integridade</a>
  <span>&nbsp;·&nbsp;</span>
  <a href="#cli">CLI</a>
  <span>&nbsp;·&nbsp;</span>
  <a href="#referencia">Referência</a>
  <span>&nbsp;·&nbsp;</span>
  <a href="#limitacoes">Limitações</a>
</h3>

</div>

<br>

O **BrowserForensics-X** encontra todos os perfis de navegador em um sistema vivo ou em uma imagem montada,
faz uma cópia com hash de cada um e analisa essas cópias offline. Ele recupera registros excluídos, junta
tudo em uma única linha do tempo em UTC, relaciona a atividade do navegador com artefatos do sistema
operacional e gera relatórios que podem ser entregues a terceiros. Tudo isso vem em **um único
`BrowserForensics-X.sh` autocontido**.

O Bash cuida da descoberta, da aquisição, do hashing, do manifesto de evidências, da cadeia de auditoria, da
execução paralela e da verificação. Os formatos que o Bash não consegue interpretar com honestidade (estruturas
internas do SQLite, LevelDB, SNSS, mozLz4, plists e formatos de cache) ficam a cargo de um motor em Python 3
que usa apenas a biblioteca padrão. Esse motor está embutido no mesmo arquivo e é gravado em um diretório
temporário privado quando a ferramenta roda.

<table>
<tr>
<td width="33%" valign="top">

### 🧭 Encontra tudo
Mais de 70 locais de instalação conhecidos no Linux, Windows e macOS: Chrome, Edge, Brave, Opera/GX, Vivaldi,
Yandex, Arc, Firefox/ESR, LibreWolf, Waterfox, Tor, Floorp, Zen, Safari, Epiphany, qutebrowser e IE/Edge
Legacy. A busca por assinatura (`--deep`) encontra o que estiver fora desses locais.

</td>
<td width="33%" valign="top">

### 🔒 Não altera nada
As fontes são apenas lidas. Cada arquivo recebe um SHA-256 antes e depois da cópia. O SQLite só abre
**cópias descartáveis** da evidência já com hash. O log de auditoria é encadeado por hash, e o `verify`
detecta a alteração de um único byte.

</td>
<td width="33%" valign="top">

### 🧬 Recupera mais
Extrai URLs de freelists, freeblocks, espaço não alocado, frames de WAL e journals de rollback do SQLite,
reconstruindo os registros. Também recupera entradas excluídas ou sobrescritas do LevelDB. Cada resultado é
classificado como **observado**, **recuperado** ou **inferido**.

</td>
</tr>
</table>

<br>

<a id="inicio"></a>

## ⚡ Início rápido

```bash
# 1. baixe o arquivo único
chmod +x BrowserForensics-X.sh

# 2. verifique o host (bash, hashing, motor Python)
./BrowserForensics-X.sh deps

# 3. valide a ferramenta no próprio laboratório (≈ 2 min, 160 verificações)
./BrowserForensics-X.sh selftest

# 4. faça a triagem desta máquina em um novo caso
./BrowserForensics-X.sh run -c ./casos/HOST01 -e "J. Silva" --case-id INC-2026-0042
```

> [!TIP]
> Feche os navegadores antes de uma aquisição ao vivo. No Windows, arquivos travados por um navegador aberto
> não podem ser copiados sem VSS. Eles são **registrados como falha, nunca ignorados em silêncio**, e o caso é
> marcado como *parcial* (código de saída `5`).

<br>

<a id="cli"></a>

## 🖥️ A CLI

A interface de terminal detecta truecolor, 256 ou 16 cores e cai para saída sem cor quando necessário. Ela
usa Unicode ou ASCII puro, se ajusta à largura do terminal e torna clicáveis os caminhos dos relatórios
(OSC 8) nos terminais que suportam. Toda a interface vai para o **stderr**, então o `stdout` fica limpo para
pipes (`timeline --format csv | …`). Quando a saída é redirecionada, a ferramenta passa sozinha a escrever sem
cor, e respeita `NO_COLOR` e `--no-color`.

<div align="center">
<img src="docs/assets/cli-run.svg" alt="run: descoberta, aquisição, análise, relatórios e o painel-resumo do caso" width="100%">
<sub>Um <code>run</code> completo no laboratório sintético incluído: 4 etapas, barras de progresso em gradiente e o resumo do caso selado.</sub>
</div>

<br>

<table>
<tr>
<td width="50%"><img src="docs/assets/cli-discover.svg" alt="discover" width="100%"><br><sub><code>discover</code> é somente leitura: lista todos os perfis, usuários e layouts encontrados.</sub></td>
<td width="50%"><img src="docs/assets/cli-verify.svg" alt="verify" width="100%"><br><sub><code>verify</code> refaz o hash das evidências, confere o manifesto, procura arquivos não registrados e valida a cadeia de auditoria e os relatórios.</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/assets/cli-timeline.svg" alt="timeline" width="100%"><br><sub><code>timeline</code> é uma única linha do tempo em UTC para todos os navegadores, colorida por classe de evidência.</sub></td>
<td width="50%"><img src="docs/assets/cli-selftest.svg" alt="selftest" width="100%"><br><sub><code>selftest</code> monta um laboratório, executa o pipeline inteiro e confere 160 verificações.</sub></td>
</tr>
</table>

<details>
<summary><b>Tela de ajuda completa</b></summary>
<br>
<img src="docs/assets/cli-help.svg" alt="help" width="100%">
</details>

<br>

## 🛰️ Pipeline

<img src="docs/assets/pipeline.svg" alt="Pipeline: descobrir, adquirir, analisar, correlacionar, reportar — com um trilho de integridade em todas as etapas" width="100%">

| Etapa | O que acontece | Saída |
|---|---|---|
| **Descobrir** | Caminhos conhecidos por SO, caminhos personalizados do `profiles.ini`, layouts de perfil único do Opera, diretórios de cache externos e artefatos do SO; busca por assinatura com `--deep`; `--source` para pastas exportadas | `profiles.tsv`, `sources.tsv` |
| **Adquirir** | Calcula o hash da fonte, copia preservando as datas (incluindo WAL/SHM/journals), calcula o hash da cópia e sela o manifesto. Links simbólicos, arquivos grandes demais e arquivos travados são **registrados**, nunca descartados em silêncio | `evidence/`, `manifest.jsonl`, `SHA256SUMS` |
| **Analisar** | Um processo paralelo por perfil. Falhas de parser ficam isoladas, então um banco corrompido não derruba o caso | `analysis/<id>/records.jsonl` |
| **Correlacionar** | Junção da linha do tempo; downloads ↔ LNK / xbel / Quarantine ↔ o arquivo no disco (tamanho, SHA-256, Zone.Identifier); cache, favicons e abas sem histórico; datas no futuro | `timeline.jsonl`, `findings.json` |
| **Reportar** | HTML (offline, com CSP restrita e todo o conteúdo escapado), JSON, CSV (protegido contra injeção de fórmulas) e Markdown, todos selados com SHA-256 | `reports/` |

<br>

<a id="cobertura"></a>

## 🧬 O que ele recupera

<table>
<tr><th align="left">Família</th><th align="left">Artefatos</th></tr>
<tr><td><b>Chromium</b><br><sub>Chrome · Edge · Brave · Opera · Vivaldi · Yandex · Arc · Thorium · …</sub></td>
<td>histórico e visitas (transição, duração) · termos de busca · downloads + cadeia de URLs + hash registrado pelo navegador · favoritos (+ os que só existem no backup) · cookies (metadados) · logins salvos (inventário) · preenchimento automático · mecanismos de busca · favicons · sites mais visitados · atalhos e previsões da barra de endereço · histórico de mídia · <b>sessões SNSS</b> · extensões + alertas de risco · preferências, permissões e marcador de "limpar dados de navegação" · <b>Local/Session Storage (LevelDB + snappy)</b> · nomes de IndexedDB · service workers · armazenamento de extensões · cache HTTP (simple e blockfile)</td></tr>
<tr><td><b>Gecko</b><br><sub>Firefox · ESR · LibreWolf · Waterfox · Tor · Floorp · Zen · …</sub></td>
<td>histórico e tipos de visita · favoritos · downloads · histórico de digitação · metadados de interação com a página · cookies · histórico de formulários <b>+ registros de exclusão</b> · logins (inventário) · favicons · <b>sessões mozLz4</b> (abas e janelas abertas/fechadas) · complementos + estado de assinatura · preferências, incluindo configurações antiforenses · permissões · localStorage LSNG e legado · IndexedDB · service workers · cache2</td></tr>
<tr><td><b>Safari / WebKit</b></td>
<td>History.db <b>+ registros de exclusão de histórico</b> · Downloads.plist · favoritos e Lista de Leitura · última sessão e abas fechadas recentemente · abas do iCloud · sites favoritos · <b>binarycookies</b> · Cache.db · LocalStorage · favicons · permissões por site · extensões</td></tr>
<tr><td><b>Outros</b></td><td>GNOME Web (Epiphany) · qutebrowser · IE / Edge Legacy <code>WebCacheV01.dat</code> (detectado e com hash)</td></tr>
<tr><td><b>Correlação com o SO</b></td><td><code>recently-used.xbel</code> no Linux · <code>QuarantineEventsV2</code> no macOS · <code>.lnk</code> de Recentes no Windows · Prefetch (executáveis de navegadores) · o arquivo baixado no disco</td></tr>
<tr><td><b>Recuperação</b></td><td>freelist / freeblocks / espaço não alocado / frames de WAL (atuais e antigos) / journals de rollback do SQLite, com reconstrução de registros e descarte de ruído · valores excluídos e sobrescritos do LevelDB</td></tr>
</table>

Cada artefato tem um nível de suporte declarado. A lista oficial sai com `./BrowserForensics-X.sh matrix`:

| Nível | Significado |
|---|---|
| ![FULL](https://img.shields.io/badge/-FULL-34d399?style=flat-square) | interpretação estruturada dos campos documentados |
| ![PARTIAL](https://img.shields.io/badge/-PARTIAL-fbbf24?style=flat-square) | estruturada, mas alguns campos ou estruturas não são decodificados |
| ![CARVE](https://img.shields.io/badge/-CARVE-a78bfa?style=flat-square) | recuperação por carving, sem garantia de completude |
| ![DETECT](https://img.shields.io/badge/-DETECT-475569?style=flat-square) | adquirido, com hash e inventariado apenas |
| ![NONE](https://img.shields.io/badge/-NONE-f87171?style=flat-square) | sem suporte |

<details>
<summary><b>Prévia do <code>matrix</code></b></summary>
<br>
<img src="docs/assets/cli-matrix.svg" alt="matriz de suporte" width="100%">
</details>

<br>

<a id="integridade"></a>

## 🔐 Integridade forense

```text
casos/INC-2026-0042/
├── case.json              metadados do caso, ambiente, opções, limitações
├── audit.log              encadeado por hash: cada linha sela a anterior
├── profiles.tsv           o que foi descoberto, e como
├── sources.tsv            exatamente quais locais foram adquiridos
├── support_matrix.tsv     os níveis de suporte vigentes neste caso
├── errors.jsonl           todo problema de aquisição/análise, nunca escondido
├── evidence/              somente leitura depois de selado
│   ├── manifest.jsonl     origem, cópia, tamanho, m/a/ctime, SHA-256 da origem + da cópia, status
│   ├── SHA256SUMS         compatível com o coreutils
│   ├── manifest.sha256    sela o manifesto + SHA256SUMS
│   └── P001/profile/…     cópias idênticas byte a byte
├── analysis/              registros, inventários, linha do tempo, achados, correlações
├── reports/               report.html · report.json · report.md · csv/ · SHA256SUMS
└── logs/
```

**Garantias**

- **As fontes são lidas, nunca gravadas.** A ferramenta nunca abre uma fonte com o SQLite. O WAL só é aplicado
  dentro de cópias de trabalho descartáveis das cópias de evidência, que são apagadas no fim (`--keep-work`
  as mantém).
- **Hash dos dois lados.** Se uma fonte muda durante a cópia, isso é detectado e marcado como
  `source-changed-during-acquisition`.
- **Evidência de adulteração.** O `verify` refaz o hash de cada cópia e falha se encontrar arquivos não
  registrados, um manifesto alterado, uma cadeia de auditoria quebrada ou relatórios modificados (código de
  saída `4`).
- **A evidência nunca é executada.** Código de extensões, scripts e binários baixados são tratados como bytes.
  A leitura de XML rejeita `DOCTYPE`/`ENTITY` (XXE). O relatório HTML roda sob uma CSP restrita com nonce, não
  carrega recursos externos e nunca torna URLs clicáveis.
- **Segredos são mascarados por padrão.** Valores de cookies e de armazenamento, dados de formulários, nomes
  de usuário, e-mails e parâmetros sensíveis de URL (`token=`, `session=` …) são substituídos por
  `[REDACTED len=N hmac=…]`. O HMAC usa uma chave por caso: o perito consegue confirmar um valor conhecido,
  mas quem lê o relatório não consegue descobri-lo por força bruta. O `--no-redact` é explícito, registrado
  no log e auditado.
- **A criptografia é respeitada.** Valores de cookies e senhas do Chromium (DPAPI / v10 / v11 / v20 /
  Keychain / libsecret), o `logins.json` do Firefox (NSS) e o Keychain são **inventariados, nunca
  descriptografados**.
- **Sem rede, nunca.** Nenhuma consulta externa, nenhuma telemetria, nenhuma verificação de atualização.

<br>

## 🧠 Classes de evidência e achados

| Classe | Significado | Exemplos |
|---|---|---|
| ![observado](https://img.shields.io/badge/-observado-34d399?style=flat-square) | lido de um registro ativo | visitas, cookies, favoritos, navegações SNSS |
| ![recuperado](https://img.shields.io/badge/-recuperado-fbbf24?style=flat-square) | reconstruído a partir de dados excluídos ou sobrescritos | URLs de freeblocks com títulos e datas, páginas antigas do WAL, valores excluídos do LevelDB |
| ![inferido](https://img.shields.io/badge/-inferido-a78bfa?style=flat-square) | deduzido por correlação ou heurística | hora de execução pelo Prefetch, cache sem histórico, lacunas nos IDs de visita |

Verificações embutidas geram **achados** com uma gravidade. Elas cobrem:

- visitas órfãs e lacunas nos IDs de visita;
- marcadores de "limpar dados de navegação" e configurações antiforenses (limpar ao fechar, modo privado
  permanente);
- registros de exclusão do histórico do Safari e do histórico de formulários do Firefox;
- downloads perigosos, ausentes, com tamanho diferente ou modificados;
- extensões instaladas fora da loja ou sem assinatura, com permissões amplas;
- dados de WAL ainda não consolidados, journals pendentes e corrupção de SQLite;
- datas no futuro ou posteriores às datas de modificação dos arquivos;
- páginas em cache, favicons ou abas sem histórico correspondente.

<br>

<a id="referencia"></a>

## 📚 Referência

<details open>
<summary><b>Comandos</b></summary>

| Comando | Função |
|---|---|
| `run` | descobrir → adquirir → analisar → reportar, do início ao fim |
| `discover` | detecta navegadores e perfis (somente leitura); `--format tsv` para scripts |
| `acquire` | aquisição controlada em um diretório de caso **novo/vazio** |
| `analyze` | interpreta, recupera, correlaciona e monta a linha do tempo (em paralelo) |
| `report` | HTML · JSON · CSV · Markdown, com filtros opcionais |
| `timeline` | consulta a linha do tempo como `table`, `csv` ou `jsonl` |
| `verify` | verificação completa da integridade de um caso |
| `selftest` | monta o laboratório, executa o pipeline e confere 160 verificações |
| `matrix` | nível de suporte de cada artefato |
| `deps` | recursos e dependências do host |

</details>

<details>
<summary><b>Opções</b></summary>

| Opção | Descrição |
|---|---|
| `-r, --root DIR` | imagem montada ou árvore exportada no lugar do sistema vivo (pode repetir) |
| `-s, --source DIR` | diretório de perfil explícito, com a família detectada automaticamente (pode repetir) |
| `--family F` | força a família do `--source`: `chromium` `firefox` `safari` `epiphany` `qutebrowser` |
| `-b, --browsers LISTA` | restringe a descoberta, ex. `chrome,edge,firefox,safari,os,ese` |
| `--deep` / `--depth N` | busca por assinatura (profundidade padrão 8) |
| `--no-os-artifacts` | ignora xbel / LNK / Prefetch / QuarantineEventsV2 |
| `-c, --case DIR` | diretório do caso |
| `--case-id ID`, `-e, --examiner NOME`, `--notes TEXTO` | metadados do caso |
| `--no-cache` / `--full` | ignora os caches HTTP / inclui os caches de JIT e GPU |
| `--max-file-size TAM` | ignora (mas registra) arquivos maiores, padrão `2G` |
| `-j, --jobs N` | análises em paralelo (padrão: nº de CPUs, máximo 8) |
| `--no-redact` | **desativa** o mascaramento (auditado) |
| `--no-recover` | não faz o carving de registros excluídos |
| `--no-fs-correlation` | não lê nem calcula hash dos arquivos baixados sob a raiz |
| `--keep-work` | mantém as cópias de trabalho do SQLite |
| `--since`, `--until` | ISO-8601; UTC a menos que haja fuso; uma data sem hora cobre o dia inteiro |
| `--domain LISTA` | domínio + subdomínios; `~texto` para busca por trecho |
| `--profile REGEX`, `--browser LISTA`, `--type LISTA`, `--class LISTA` | filtros de relatório e linha do tempo |
| `--formats LISTA`, `-o, --out DIR` | formatos e destino dos relatórios |
| `--format`, `--limit` | saída da linha do tempo e do discover |
| `-v`, `-q`, `--no-color`, `--keep-tmp` | verbosidade e saída |

Variáveis de ambiente: `NO_COLOR=1`, `BFX_ASCII=1` (glifos ASCII), `BFX_PYTHON=/caminho/python3`,
`BFX_COLOR_DEPTH=0|4|8|24`, `BFX_NO_BANNER=1`.

</details>

<details>
<summary><b>Receitas</b></summary>

```bash
# imagem do Windows montada, navegadores Chromium + artefatos do SO, 4 processos
./BrowserForensics-X.sh run -r /mnt/evidencia/C -c ./casos/IMG01 -b chrome,edge,brave,os -j 4

# uma única pasta de perfil exportada
./BrowserForensics-X.sh run -s ./export/Default -c ./casos/EXP01

# adquirir no host suspeito (sem Python) e analisar na estação do laboratório
./BrowserForensics-X.sh acquire -c /media/usb/CASO01
./BrowserForensics-X.sh analyze -c /media/usb/CASO01 && ./BrowserForensics-X.sh report -c /media/usb/CASO01

# um dia, um domínio, em CSV para planilha
./BrowserForensics-X.sh timeline -c ./casos/IMG01 --since 2024-03-15 --until 2024-03-15 \
    --domain example.com --format csv > dia.csv

# só evidências recuperadas e downloads, em HTML + CSV
./BrowserForensics-X.sh report -c ./casos/IMG01 --type download,recovered_url --formats html,csv

# antes de entregar o caso
./BrowserForensics-X.sh verify -c ./casos/IMG01
```

</details>

<details>
<summary><b>Códigos de saída</b></summary>

| Código | Significado |
|---|---|
| `0` | sucesso |
| `1` | erro |
| `2` | erro de uso / validação |
| `3` | dependência ausente (ex. Python para o `analyze`) |
| `4` | falha de integridade (`verify`) |
| `5` | concluído com resultados parciais (arquivos travados, erros de parser) |

</details>

<details>
<summary><b>Requisitos e plataformas</b></summary>

| | Necessário | Observações |
|---|---|---|
| **Bash** | ≥ 4.4 | o macOS vem com a 3.2 → `brew install bash` |
| **coreutils** | `find cp sha256sum`/`shasum`/`openssl`, `stat`, `xargs` … | as ferramentas GNU processam em lote mais rápido; há alternativas BSD |
| **Python** | ≥ 3.8, só a biblioteca padrão | necessário para `analyze`/`report`/`timeline`/`selftest`; **não** para `discover`/`acquire`/`verify` |
| `sqlite3`, `jq` | não necessários | |

**Linux** é nativo. **Windows** roda no Git Bash / MSYS2 / Cygwin / WSL; no WSL também varre `/mnt/c/Users`.
**macOS** exige Acesso Total ao Disco para o terminal ler os dados do Safari (arquivos ilegíveis aparecem como
erros).

</details>

<br>

<a id="limitacoes"></a>

## 🧪 Validação e limitações

Esta ferramenta foi feita para dizer exatamente o que fez e o que não fez.

- **Self-test (160 verificações).** Todos os parsers rodam sobre artefatos sintéticos que seguem o esquema de
  cada navegador, em layouts de Linux, Windows e macOS. As verificações cobrem:
  - decodificadores (snappy, LZ4, CRC32C, varints, protobuf, pickles SNSS, binarycookies, LNK) e a conversão
    para UTC de 7 formatos de data;
  - a recuperação de registros excluídos e o filtro de ruído;
  - o mascaramento (15 segredos plantados nunca podem aparecer em nenhuma saída) e o escape de títulos hostis
    no HTML;
  - a validação da CLI, a trava do caso e a detecção de adulteração na evidência e no log de auditoria;
  - a aquisição sem Python e a preservação das fontes do laboratório (conteúdo e data de modificação).
- **Validado com dados gerados por navegadores reais.** Perfis criados pelo **Chrome e pelo Edge** reais
  (Windows): histórico e transições, cookies, sessões SNSS, localStorage, cache blockfile, service workers e
  nomes de IndexedDB.
- **Ainda não validado com dados de navegadores reais.** Firefox, Safari, Epiphany, qutebrowser, o formato
  simple-cache do Chromium e a contagem de registros do IndexedDB. Eles estão cobertos só pelo laboratório
  sintético. Mudanças de esquema são tratadas coluna a coluna e aparecem como erro de parser, nunca em
  silêncio.
- **Sem suporte.**
  - O `WebCacheV01.dat` (ESE) e o conteúdo do Prefetch (MAM) não são decodificados. Os dois são adquiridos e
    recebem hash, e as datas dos arquivos do Prefetch são usadas como sinal *inferido*.
  - Segredos não são descriptografados, por princípio.
  - O layout de janelas e grupos de abas não é reconstruído a partir do SNSS, e os blobs `SessionState` do
    Safari não são decodificados.
  - Os valores de IndexedDB (serialização V8 / structured clone) só passam por carving de URLs.
- **O carving não garante completude.** Dados sobrescritos por `secure_delete`, `VACUUM` ou compactação do
  LevelDB se perderam.
- **A aquisição ao vivo no Windows não usa VSS.** Feche os navegadores ou adquira a partir de uma imagem ou
  snapshot.

<br>

<div align="center">

<sub>Feito para peritos que precisam explicar cada byte.<br>
<b>BrowserForensics-X</b> · descobrir · adquirir · recuperar · correlacionar · reportar</sub>

</div>
