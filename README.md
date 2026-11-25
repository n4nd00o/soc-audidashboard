# SOC AudiDashboard

> **Projeto estudantil** · *Student project* · [English version](README.en.md)
>
> Este é um projeto **estudantil**, open source, feito para portfólio. Não é um produto certificado
> nem possui garantias de qualquer tipo.

> **AVISO DE USO ÉTICO E AUTORIZADO.** Use esta ferramenta **somente** em sistemas que você possui ou
> para os quais tem **autorização explícita e por escrito** para auditar. Executar auditorias contra
> alvos sem autorização pode ser crime. Os autores não se responsabilizam pelo mau uso.

## O que é

Equipes de TI/SI mantêm dezenas de scripts de auditoria (Bash, PowerShell, Python) espalhados e
executados à mão. O SOC AudiDashboard reúne esses scripts como **plugins** num único aplicativo:
o analista executa as auditorias a partir da própria máquina, os achados (findings) são
padronizados, classificados por severidade e enviados de forma segura a um servidor central, e um
**dashboard web** mostra nível de ameaça, suspeitas de comprometimento, tendências e recomendações.

## Arquitetura

```
┌──────────── Máquina do analista ────────────┐          ┌──────── Servidor central (docker compose) ────────┐
│ App desktop (PySide6)                       │  mTLS    │ Reverse proxy (TLS 1.3 + verificação de cert)     │
│  ├ catálogo de plugins / visualizar código  │ ───────► │ API FastAPI  /api/v1  (ingestão, catálogo)       │
│  ├ alvos (sincronizados do servidor)        │  HTTPS   │ Dashboard FastAPI+HTMX (sessão + MFA)  ◄── navegador
│  ├ runner (subprocesso isolado, timeout)    │          │ PostgreSQL (achados, ativos, usuários, auditoria) │
│  ├ sanitizer (remove segredos/PII)          │          │ CA interna (emite certificados de dispositivo)    │
│  └ credenciais → keyring do SO (nunca sobem)│          └───────────────────────────────────────────────────┘
└─────────────────────────────────────────────┘
        │ SSH / WinRM / APIs de nuvem / rede
        ▼
   Alvos: Linux, Windows, AWS, Azure, GCP, M365, rede, web
```

## Alinhamento com ISO 27001/27002 e LGPD

O projeto *se alinha* a controles da ISO/IEC 27001/27002 e a princípios da LGPD (minimização,
sanitização na origem, segurança por design). Isso **não** é certificação nem parecer jurídico;
é apenas uma referência de projeto.

## Início rápido (por enquanto, apenas CLI)

Requer Python 3.12+ e [uv](https://docs.astral.sh/uv/).

```bash
git clone <url-do-repositorio>
cd <diretorio-do-repositorio>
uv sync
uv run pytest -q

# CLI
uv run audidash plugins list
uv run audidash plugins show http-security-headers
uv run audidash run http-security-headers --target example.com --target-type web \
    --param url=https://example.com --yes
```

Credenciais **não** são aceitas pela linha de comando (vazariam no histórico do shell e no argv);
a entrada de credenciais chega com o app desktop (keyring do SO).

## Como escrever um plugin

Plugins são scripts em qualquer linguagem com um manifesto e saída JSON. Veja o guia em
[`docs/plugins.md`](docs/plugins.md) (será criado na Tarefa 7 do Plano 1).

## Roadmap

- **Plano 1** — fundação e núcleo (`audidash-core`: schemas, runner, sanitizer, scoring, SDK).
- **Plano 2** — servidor (API FastAPI, banco de dados, mTLS).
- **Plano 3** — dashboard web (FastAPI + HTMX, login com MFA).
- **Plano 4** — app desktop (PySide6) e ambiente de demonstração.

## Contribuindo e segurança

Veja [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) e
[SECURITY.md](SECURITY.md). Vulnerabilidades: use o relato privado do GitHub, nunca issues públicas.

## Licença

Apache-2.0. Copyright 2026 SOC AudiDashboard contributors. Veja [LICENSE](LICENSE).
