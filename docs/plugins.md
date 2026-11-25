# Escrevendo plugins (PT-BR)

[English version](plugins.en.md)

O SOC AudiDashboard é um projeto de portfólio de estudante. Use plugins **somente em infraestrutura que você tem autorização para auditar**. O projeto é alinhado com (não certificado para) ISO 27001/27002 e LGPD.

Um plugin é um programa pequeno que recebe um alvo pela entrada padrão (stdin), faz as verificações e imprime os achados em JSON na saída padrão (stdout). Pode ser escrito em Python, PowerShell ou Bash.

## Estrutura de diretórios

```
plugins/
  meu-plugin/
    plugin.yaml      # manifesto (obrigatório)
    run.py           # ponto de entrada (qualquer arquivo listado em `files`)
    helpers/...      # módulos extras opcionais (importáveis pelo entrypoint), devem constar em `files`
```

Todo arquivo necessário ao plugin deve constar em `files` com o hash sha256. O runner copia os arquivos para um diretório temporário, confere os hashes da cópia e só então executa.

## Referência do `plugin.yaml`

| Campo | Tipo | Regras |
|---|---|---|
| `id` | string | `^[a-z0-9][a-z0-9-]{2,63}$` |
| `name` | string | não vazio |
| `version` | string | SemVer (`0.1.0`) |
| `author` | string | não vazio |
| `license` | string | não vazio (ex.: `Apache-2.0`) |
| `description` | string | não vazio |
| `runtime` | enum | `python`, `powershell` ou `bash` |
| `execution` | enum | `local` ou `remote`. **A execução remota chega em uma versão futura; por ora use `local`.** |
| `entrypoint` | string | caminho POSIX relativo (sem `..`, sem unidade, sem `\`), deve estar em `files` |
| `files` | mapa | caminho relativo -> sha256 em hex (64 caracteres minúsculos) |
| `targets` | lista | ao menos um de `linux`, `windows`, `aws`, `azure`, `gcp`, `m365`, `network`, `web`, `local` |
| `connection` | enum | `ssh`, `winrm`, `cloud_api`, `network`, `local` |
| `permissions` | lista | ao menos um item descrevendo o que o plugin precisa (ex.: `read-only`) |
| `references` | lista | links opcionais (normas, documentação) |
| `parameters` | mapa | opcional; cada chave aponta para `{type, default, description}`, com `type` entre `string`, `integer`, `boolean`, `list` |

Campos desconhecidos são rejeitados. **Não existe** campo `trust` (veja os níveis de confiança abaixo).

```yaml
id: demo-plugin
name: Plugin de demonstração
version: 0.1.0
author: Seu Nome
license: Apache-2.0
description: Plugin de exemplo
runtime: python
execution: local
entrypoint: run.py
files:
  run.py: "<sha256 de run.py>"
targets: [local]
connection: local
permissions: [read-only]
parameters:
  max_items:
    type: integer
    default: 10
    description: Máximo de itens a verificar
```

## Entrada (stdin)

O plugin recebe um único objeto JSON no stdin:

```json
{
  "target": "host-01",
  "target_type": "linux",
  "parameters": {"max_items": 10},
  "credentials": {"password": "..."}
}
```

`credentials` fica vazio quando o plugin não precisa de credenciais. As credenciais são entregues **somente** pelo stdin: nunca por argv, nunca por variáveis de ambiente.

## Saída (stdout)

Imprima exatamente um objeto JSON e mais nada no stdout:

```json
{
  "findings": [
    {
      "id": "DEMO-1",
      "title": "Título curto",
      "severity": "medium",
      "category": "misconfiguration",
      "target": "host-01",
      "evidence": "o que foi observado",
      "recommendation": "como corrigir",
      "references": ["https://example.org/doc"],
      "item_key": "chave-estavel-opcional"
    }
  ],
  "warnings": ["verificações que não puderam rodar"]
}
```

| Campo | Regras |
|---|---|
| `id` | `^[A-Z0-9][A-Z0-9_-]{1,63}$` |
| `title` | 1 a 200 caracteres |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `category` | `misconfiguration`, `vulnerability`, `suspicious`, `compliance` |
| `target` | o alvo auditado (copie da entrada) |
| `evidence`, `recommendation` | texto |
| `references` | lista de strings |
| `item_key` | opcional; diferencia vários achados com o mesmo `id` no mesmo alvo (ex.: um caminho de arquivo) |

Saída inválida faz a execução falhar. O runner sanitiza as evidências (strings parecidas com segredos são removidas) e limita o tamanho. Use o stderr para diagnóstico; saia com código diferente de zero em erros fatais.

O runner executa o plugin com ambiente limpo, diretório de trabalho temporário, timeout e limite de tamanho do stdout.

## Exemplo: Python (com o SDK)

O `audidash_sdk` usa apenas a biblioteca padrão e é tornado importável pelo runner. Plugins Python rodam com `-I -S`: **somente a biblioteca padrão e o `audidash_sdk` são importáveis** (não `audidash_core`, `pydantic` etc.).

```python
from typing import Any

from audidash_sdk import Reporter, run


def main(data: dict[str, Any], report: Reporter) -> None:
    limit = int(data["parameters"].get("max_items", 10))
    if limit > 5:
        report.add(
            id="DEMO-1",
            title="Limite acima do valor recomendado",
            severity="low",
            category="compliance",
            evidence=f"max_items={limit}",
            recommendation="Use 5 ou menos.",
        )
    report.warn("aviso de exemplo")


run(main)
```

API do SDK: `read_input() -> dict`, `Reporter.add(id, title, severity, category, evidence="", recommendation="", references=None, item_key=None)` (levanta `ValueError` para severidade ou categoria desconhecida), `Reporter.warn(msg)`, `Reporter.emit()`, `run(main)`. O `run` preenche `target` a partir da entrada, imprime o JSON e, em exceção não tratada, escreve `Tipo: mensagem` no stderr e sai com código 1.

## Exemplo: PowerShell

Plugins PowerShell e Bash imprimem o JSON por conta própria. Use `execution: local` por enquanto.

```powershell
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$findings = @()
if ($payload.target -eq 'host-01') {
    $findings += @{
        id = 'DEMO-PS-1'; title = 'Achado de exemplo'; severity = 'info'
        category = 'compliance'; target = $payload.target
        evidence = 'demo'; recommendation = 'nenhuma'
        references = @(); item_key = $null
    }
}
$out = [ordered]@{ findings = @($findings); warnings = @() }
ConvertTo-Json -InputObject $out -Depth 5 -Compress
```

`ConvertTo-Json -InputObject` mantém `findings` como array mesmo com um único elemento.

## Exemplo: Bash

```bash
#!/usr/bin/env bash
set -euo pipefail
payload="$(cat)"
target="$(printf '%s' "$payload" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target"])')"
printf '{"findings":[{"id":"DEMO-SH-1","title":"Achado de exemplo","severity":"info","category":"compliance","target":"%s","evidence":"demo","recommendation":"nenhuma","references":[],"item_key":null}],"warnings":[]}\n' "$target"
```

Cuidado ao inserir dados da entrada no JSON manualmente; prefira uma ferramenta que faça o escape (`jq`, `python3`).

## Níveis de confiança

Os plugins aparecem com um nível: `official`, `verified` ou `community`. O nível é **atribuído pelo catálogo**, nunca pelo manifesto: uma chave `trust` no `plugin.yaml` é rejeitada. O autor não consegue promover o próprio plugin.

## Calculando os hashes

Depois de qualquer edição, recalcule `files`. Com a CLI (`audidash plugins hash`, já disponível):

```
audidash plugins hash <dir>
```

Até lá, use a alternativa em Python:

```python
from pathlib import Path
from audidash_core.manifest import compute_hashes

print(compute_hashes(Path("plugins/meu-plugin"), ["run.py"]))
```

Cole o resultado em `files` no `plugin.yaml`. Qualquer alteração em um arquivo listado sem atualizar o hash faz a execução falhar com erro de integridade.

## Regras de segurança

- Não abra conexões de rede além do alvo informado.
- Credenciais chegam só pelo stdin. Nunca em argv ou variáveis de ambiente, e nunca as imprima, registre ou grave em achados, avisos ou stderr.
- Não modifique o sistema auditado; peça só as permissões necessárias e liste-as em `permissions`.
- Não escreva fora do seu diretório de trabalho temporário.
- Não baixe nem execute código em tempo de execução.
- Mantenha as evidências mínimas: sem segredos nem dados pessoais.

## Uso ético

Audite apenas sistemas seus ou com autorização expressa e por escrito. Varreduras não autorizadas podem ser ilegais. Este é um projeto de estudante, fornecido sem garantia; é alinhado com, e não certificado para, ISO 27001/27002 e LGPD.
