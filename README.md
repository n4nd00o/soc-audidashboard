# SOC AudiDashboard

![CI](https://github.com/n4nd00o/soc-audidashboard/actions/workflows/ci.yml/badge.svg)

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
┌──── Máquina do analista ─────┐            ┌──────────── Servidor (docker compose) ────────────────────┐
│ CLI `audidash` (hoje)        │            │ Caddy                                                      │
│  ├ catálogo/plugins assinados│  mTLS      │  ├ :9443  API dos dispositivos (mTLS obrigatório)          │
│  ├ runner (subprocesso,      │ ─────────► │  └ :8443  dashboard + /enroll (TLS, sem /api)  ◄── navegador
│  │  timeout, sem shell)      │  :9443     │        │ rede interna + segredo do proxy                   │
│  ├ sanitizer (segredos/PII)  │            │ App FastAPI + HTMX (API /api/v1, dashboard, sessão + TOTP) │
│  └ cert de dispositivo (CA)  │            │        │                                                   │
└──────────────────────────────┘            │ PostgreSQL (ativos, achados, execuções, usuários, auditoria)│
        │ rede                              │ CA interna (EC P-256, emite certificados de dispositivo)   │
        ▼                                   └────────────────────────────────────────────────────────────┘
   Alvos auditados (web, TLS, portas, ...)
```

O que existe hoje (`0.2.0-alpha.1`):

- **Servidor** (`packages/audidash-server`): API de ingestão (`/api/v1`, com deduplicação e
  resolução automática de achados) e **dashboard** FastAPI + HTMX: visão geral (medidor e
  tendência em SVG), ativos, achados com ciclo de vida, execuções, lista de plugins permitidos,
  dispositivos/tokens de inscrição, usuários e visualizador da trilha de auditoria.
- **Autenticação**: Argon2id, TOTP obrigatório, bloqueio de conta, limite de tentativas,
  sessões com CSRF e papéis (RBAC); trilha de auditoria encadeada por hash (`audit verify`).
- **Dispositivos**: CA interna, inscrição com token de uso único + verificação da impressão
  digital da CA, mTLS terminado no Caddy (`deploy/`).
- **Cliente** (`packages/audidash-core`): `audidash enroll | login | assets | run --upload | demo
  | plugins list --sync-verified`.
- **Ainda não existe**: app desktop e execução remota (veja o Roadmap).

## Raiz de confiança

O nível de confiança (`official`, `verified`, `community`) vem do catálogo assinado (Ed25519), nunca do
manifesto do plugin. Os plugins incluídos são assinados com a chave do projeto
(`packages/audidash-core/src/audidash_core/keys/catalog.pub`) e aparecem como `official`; os demais
são `community` e pedem confirmação. Detalhes em [docs/plugins.md](docs/plugins.md#níveis-de-confiança).

## Alinhamento com ISO 27001/27002 e LGPD

O projeto *se alinha* a controles da ISO/IEC 27001/27002 e a princípios da LGPD (minimização,
sanitização na origem, segurança por design). Isso **não** é certificação nem parecer jurídico;
é apenas uma referência de projeto.

## Demo em 5 minutos

Requer **Docker** (Compose v2), Python 3.12+ e [uv](https://docs.astral.sh/uv/). Tudo roda em
`localhost`; os alvos de laboratório são **intencionalmente vulneráveis** e ficam presos a
`127.0.0.1`. Detalhes e portas em [`deploy/README.md`](deploy/README.md).

```bash
git clone https://github.com/n4nd00o/soc-audidashboard.git
cd soc-audidashboard
uv sync

# 1. segredos (URL-safe, >= 32 caracteres): substitua cada CHANGE_ME por um valor gerado com
#    python -c "import secrets;print(secrets.token_urlsafe(48))"
cp deploy/.env.example deploy/.env

# 2. suba a pilha (PostgreSQL + servidor + Caddy + 3 alvos de laboratório)
docker compose -f deploy/docker-compose.yml up -d --build

# 3. conta de administrador (pede a senha e mostra o segredo TOTP)
docker compose -f deploy/docker-compose.yml exec server audidash-server create-admin --username admin

# 4. impressão digital da CA interna e token de inscrição (exibido uma única vez)
docker compose -f deploy/docker-compose.yml exec server audidash-server show-ca-fingerprint
docker compose -f deploy/docker-compose.yml exec server audidash-server create-enrollment-token --created-by admin

# 5. no host: inscreva este computador, faça login e rode a demo contra os alvos de laboratório
uv run audidash enroll --server https://localhost:8443 --api https://localhost:9443 \
    --name meu-notebook --token=<TOKEN> --ca-fingerprint <SHA-256>
uv run audidash login
uv run audidash demo
```

Abra <https://localhost:8443> (o navegador avisará sobre a CA interna do Caddy), entre com o
administrador e o código TOTP e veja ativos, achados e execuções. Para apagar tudo:
`docker compose -f deploy/docker-compose.yml down -v`.

> Capturas de tela previstas (ainda não adicionadas): veja [`docs/img/README.md`](docs/img/README.md).

## Desenvolvimento local

```bash
uv sync
uv run pytest -q
uv run audidash plugins list
uv run audidash plugins show http-security-headers
uv run audidash run http-security-headers --target example.com --target-type web \
    --param url=https://example.com --yes
```

Credenciais **não** são aceitas pela linha de comando (vazariam no histórico do shell e no argv).
A suíte de testes do servidor usa SQLite por padrão; o CI também a executa contra PostgreSQL
(`AUDIDASH_TEST_DATABASE_URL`). Atenção: as fixtures **apagam o schema `public`** desse banco, por
isso só aceitam um banco descartável cujo nome termine em `_test` (ou contenha `test` em
`localhost`); qualquer outro nome aborta a execução.

## Como escrever um plugin

Plugins são scripts em qualquer linguagem com um manifesto e saída JSON. Veja o guia em
[`docs/plugins.md`](docs/plugins.md).

## Roadmap

- **Plano 1** (`0.1.0-alpha.1`): fundação e núcleo (schemas, runner, sanitizer, scoring, SDK, CLI).
- **Plano 2** (`0.2.0-alpha.1`): servidor e dashboard (API, PostgreSQL, CA interna e mTLS, MFA,
  auditoria, demonstração com Docker Compose).
- **Plano 3**: app desktop (PySide6) reutilizando o cliente da CLI.
- **Plano 4**: execução remota (SSH/WinRM) e plugins para Linux e Windows.

## Contribuindo e segurança

Veja [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) e
[SECURITY.md](SECURITY.md). Vulnerabilidades: use o relato privado do GitHub, nunca issues públicas.

## Licença

Apache-2.0. Copyright 2026 SOC AudiDashboard contributors. Veja [LICENSE](LICENSE).
