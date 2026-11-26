# Mapeamento ISO/IEC 27001:2022 Annex A / 27002:2022

> **EN note:** This table maps controls implemented (or planned) in SOC AudiDashboard to
> ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022 control numbers. It is a design *alignment*,
> **not a certification** and not an audit opinion. Status reflects the code at
> `0.2.0-alpha.1` (Plans 1 and 2); "planned" items are not implemented yet.

**Alinhamento, não certificação.** O SOC AudiDashboard é um projeto estudantil. Esta tabela
relaciona o que o código faz hoje (ou pretende fazer) a controles da ISO/IEC 27001:2022 (Anexo A)
e 27002:2022. Não há certificação, auditoria externa nem garantia de conformidade.

| Controle (27002:2022) | Tema | Como o projeto se alinha | Status | Onde no código |
|---|---|---|---|---|
| 5.34 Privacidade e proteção de DP | Dados pessoais | Achados são sanitizados na origem (cliente), antes de qualquer armazenamento ou exibição; e-mails, CPF, telefones e segredos são mascarados | implemented | `packages/audidash-core/src/audidash_core/sanitizer.py`; aplicado em `runner.py` |
| 8.11 Mascaramento de dados | Dados | Padrões de credenciais, chaves privadas e dados pessoais substituídos por `[REDACTED:...]`; evidência truncada em 2000 caracteres | implemented | `sanitizer.py`, `tests/test_sanitizer.py` |
| 8.24 Uso de criptografia | Criptografia | Catálogo de plugins assinado com Ed25519; CA interna (EC P-256) que emite certificados de dispositivo (validade de 90 dias) para mTLS; chave da CA cifrada em repouso com `AUDIDASH_CA_PASSPHRASE` e nunca sobrescrita; senhas com Argon2id; segredos TOTP cifrados | implemented | `catalog.py`, `tools/sign_catalog.py`, `packages/audidash-server/src/audidash_server/ca.py`, `packages/audidash-server/src/audidash_server/auth/passwords.py`, `packages/audidash-server/src/audidash_server/auth/totp.py` |
| 8.19 Instalação de software em sistemas operacionais | Integridade | Cada plugin tem hashes SHA-256 de seus arquivos no manifesto, verificados antes de executar; nível de confiança é atribuído pelo catálogo, nunca pelo manifesto | implemented | `manifest.py` (`verify_integrity`), `catalog.py` |
| 8.7 Proteção contra malware | Execução segura | Plugins rodam em subprocesso isolado, sem shell, com ambiente mínimo, limites de tempo/saída e encerramento de toda a árvore de processos (Job Object / `killpg`); plugins `community` pedem confirmação | implemented | `proc.py`, `runner.py` |
| 8.28 Codificação segura | Desenvolvimento | Tipagem estrita (mypy), lint com regras de segurança (ruff `S`), SAST (bandit), validação de entradas com Pydantic, caminhos validados contra *path traversal* | implemented | `pyproject.toml`, `.github/workflows/ci.yml` |
| 8.25 Ciclo de vida de desenvolvimento seguro | Desenvolvimento | CI obrigatório (testes, cobertura >= 85 %, lint, tipos, SAST), CodeQL, varredura de segredos, política de segurança | implemented | `.github/workflows/`, `SECURITY.md`, `CONTRIBUTING.md` |
| 8.29 Testes de segurança no desenvolvimento | Desenvolvimento | Suíte de testes inclui casos adversariais (traversal, injeção de caracteres de controle, vazamento de segredos, estouro de saída) | implemented | `packages/audidash-core/tests/`, `plugins/tests/` |
| 8.8 Gestão de vulnerabilidades técnicas | Vulnerabilidades | `pip-audit` no CI, Dependabot semanal (uv e GitHub Actions), `uv.lock` com instalação `--locked` | implemented | `.github/workflows/ci.yml`, `.github/dependabot.yml`, `uv.lock` |
| 8.32 Gestão de mudanças | Mudanças | Modelo de pull request com checklist, CODEOWNERS, CI exigido e proteção de branch habilitada no GitHub | implemented | `.github/pull_request_template.md`, `.github/CODEOWNERS`, `.github/workflows/ci.yml` |
| 5.15 Controle de acesso / 8.2 Direitos de acesso privilegiado / 8.3 Restrição de acesso à informação | Acesso | Papéis (RBAC) aplicados nas rotas do dashboard e da API; dispositivos autenticados por certificado (mTLS) e token de curta duração, com revogação | implemented | `packages/audidash-server/src/audidash_server/auth/rbac.py`, `packages/audidash-server/src/audidash_server/api/deps.py`, `packages/audidash-server/tests/test_rbac.py` |
| 8.5 Autenticação segura | Autenticação | Senhas com Argon2id, TOTP obrigatório (sem reutilização de código), bloqueio de conta (5 falhas, 15 min), limite de tentativas por IP, sessões com cookie `__Host-`, expiração por inatividade e absoluta, CSRF | implemented | `packages/audidash-server/src/audidash_server/auth/passwords.py`, `packages/audidash-server/src/audidash_server/auth/totp.py`, `packages/audidash-server/src/audidash_server/auth/lockout.py`, `packages/audidash-server/src/audidash_server/auth/ratelimit.py`, `packages/audidash-server/src/audidash_server/auth/sessions.py`, `packages/audidash-server/src/audidash_server/auth/csrf.py` |
| 8.20 Segurança de redes / 8.21 Segurança de serviços de rede | Rede | Caddy termina TLS; a API de dispositivos fica em listener separado com mTLS obrigatório; `/api` não é servido no listener do dashboard; app e banco numa rede Docker interna sem saída; cabeçalhos do proxy só são aceitos com o segredo do proxy | implemented | `deploy/Caddyfile`, `deploy/docker-compose.yml`, `packages/audidash-server/src/audidash_server/proxy.py`, `packages/audidash-server/src/audidash_server/security_headers.py` |
| 8.10 Exclusão de informação (retenção) | Dados | Execuções e achados além da janela de retenção (padrão 365 dias) são removidos por `audidash-server purge`; a trilha de auditoria é preservada | implemented | `packages/audidash-server/src/audidash_server/services/retention.py`, `packages/audidash-server/src/audidash_server/cli.py` (`purge`) |
| 5.36 Conformidade com políticas e normas | Governança | Política de divulgação responsável e aviso de uso ético | implemented | `SECURITY.md`, `README.md` |
| 8.15 Registro de eventos (*logging*) | Registro | Trilha de auditoria da autenticação, administração e ingestão, encadeada por hash (cada registro inclui o hash do anterior); `audidash-server audit verify` detecta adulteração; visualizador no dashboard | implemented | `packages/audidash-server/src/audidash_server/audit.py`, `packages/audidash-server/src/audidash_server/web/routes_audit.py`, `packages/audidash-server/src/audidash_server/cli.py` (`audit verify`) |
| 8.16 Atividades de monitoramento | Monitoramento | Dashboard com nível de ameaça, tendência, achados e execuções; ainda sem alertas ativos nem integração com SIEM | implemented (parcial) | `packages/audidash-server/src/audidash_server/web/routes_overview.py`, `packages/audidash-server/src/audidash_server/web/queries.py` |
| 5.24 / 5.26 Gestão de incidentes | Incidentes | Fluxo de resposta a incidentes sobre achados críticos | planned | n/a |

## Limitações

- A cobertura é parcial: apenas controles diretamente relevantes a uma ferramenta de auditoria
  executada na estação do analista.
- Veja *Limitações conhecidas* em [`SECURITY.md`](../../SECURITY.md).
- "implemented" significa que existe código e teste; não significa que o controle esteja
  completo ou que tenha sido avaliado por terceiros.
