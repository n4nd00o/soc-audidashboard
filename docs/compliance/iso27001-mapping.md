# Mapeamento ISO/IEC 27001:2022 Annex A / 27002:2022

> **EN note:** This table maps controls implemented (or planned) in SOC AudiDashboard to
> ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022 control numbers. It is a design *alignment*,
> **not a certification** and not an audit opinion. Status reflects the code at
> `0.1.0-alpha.1` (Plan 1); "planned" items are scheduled for Plan 2.

**Alinhamento, não certificação.** O SOC AudiDashboard é um projeto estudantil. Esta tabela
relaciona o que o código faz hoje (ou pretende fazer) a controles da ISO/IEC 27001:2022 (Anexo A)
e 27002:2022. Não há certificação, auditoria externa nem garantia de conformidade.

| Controle (27002:2022) | Tema | Como o projeto se alinha | Status | Onde no código |
|---|---|---|---|---|
| 5.34 Privacidade e proteção de DP | Dados pessoais | Achados são sanitizados na origem (cliente), antes de qualquer armazenamento ou exibição; e-mails, CPF, telefones e segredos são mascarados | implemented | `packages/audidash-core/src/audidash_core/sanitizer.py`; aplicado em `runner.py` |
| 8.11 Mascaramento de dados | Dados | Padrões de credenciais, chaves privadas e dados pessoais substituídos por `[REDACTED:...]`; evidência truncada em 2000 caracteres | implemented | `sanitizer.py`, `tests/test_sanitizer.py` |
| 8.24 Uso de criptografia | Criptografia | Catálogo de plugins assinado com Ed25519; verificação da assinatura antes de conceder confiança `official` | implemented | `catalog.py`, `tools/sign_catalog.py` |
| 8.19 Instalação de software em sistemas operacionais | Integridade | Cada plugin tem hashes SHA-256 de seus arquivos no manifesto, verificados antes de executar; nível de confiança é atribuído pelo catálogo, nunca pelo manifesto | implemented | `manifest.py` (`verify_integrity`), `catalog.py` |
| 8.7 Proteção contra malware | Execução segura | Plugins rodam em subprocesso isolado, sem shell, com ambiente mínimo, limites de tempo/saída e encerramento de toda a árvore de processos (Job Object / `killpg`); plugins `community` pedem confirmação | implemented | `proc.py`, `runner.py` |
| 8.28 Codificação segura | Desenvolvimento | Tipagem estrita (mypy), lint com regras de segurança (ruff `S`), SAST (bandit), validação de entradas com Pydantic, caminhos validados contra *path traversal* | implemented | `pyproject.toml`, `.github/workflows/ci.yml` |
| 8.25 Ciclo de vida de desenvolvimento seguro | Desenvolvimento | CI obrigatório (testes, cobertura >= 85 %, lint, tipos, SAST), CodeQL, varredura de segredos, política de segurança | implemented | `.github/workflows/`, `SECURITY.md`, `CONTRIBUTING.md` |
| 8.29 Testes de segurança no desenvolvimento | Desenvolvimento | Suíte de testes inclui casos adversariais (traversal, injeção de caracteres de controle, vazamento de segredos, estouro de saída) | implemented | `packages/audidash-core/tests/`, `plugins/tests/` |
| 8.8 Gestão de vulnerabilidades técnicas | Vulnerabilidades | `pip-audit` no CI, Dependabot semanal (uv e GitHub Actions), `uv.lock` com instalação `--locked` | implemented | `.github/workflows/ci.yml`, `.github/dependabot.yml`, `uv.lock` |
| 8.32 Gestão de mudanças | Mudanças | Modelo de pull request com checklist, CODEOWNERS, CI exigido; proteção de branch deve ser habilitada pelo mantenedor no GitHub | implemented (proteção de branch: manual) | `.github/pull_request_template.md`, `.github/CODEOWNERS` |
| 5.36 Conformidade com políticas e normas | Governança | Política de divulgação responsável e aviso de uso ético | implemented | `SECURITY.md`, `README.md` |
| 8.15 Registro de eventos (*logging*) | Registro | Trilha de auditoria das execuções (quem, quando, o quê) | planned (Plan 2) | n/a |
| 8.16 Atividades de monitoramento | Monitoramento | Painel com histórico e alertas | planned (Plan 2) | n/a |
| 5.24 / 5.26 Gestão de incidentes | Incidentes | Fluxo de resposta a incidentes sobre achados críticos | planned | n/a |

## Limitações

- A cobertura é parcial: apenas controles diretamente relevantes a uma ferramenta de auditoria
  executada na estação do analista.
- Veja *Limitações conhecidas* em [`SECURITY.md`](../../SECURITY.md).
- "implemented" significa que existe código e teste; não significa que o controle esteja
  completo ou que tenha sido avaliado por terceiros.
