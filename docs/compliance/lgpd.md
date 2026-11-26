# Alinhamento com a LGPD (Lei nº 13.709/2018)

> **EN note:** Mapping of implemented/planned project controls to Brazil's LGPD (general data
> protection law). It is a design *alignment*, **not legal advice and not a certification**.

**Alinhamento, não certificação.** Este documento não é parecer jurídico. Quem opera a
ferramenta em uma organização continua sendo o responsável (controlador/operador) pelo
tratamento de dados pessoais.

| Dispositivo | Princípio / exigência | Como o projeto se alinha | Status | Onde no código |
|---|---|---|---|---|
| Art. 6º, I (finalidade) | Propósitos legítimos e específicos | Ferramenta de auditoria de segurança; aviso de uso ético e autorizado em README e SECURITY | implemented | `README.md`, `SECURITY.md` |
| Art. 6º, III (necessidade / minimização) | Limitar ao mínimo necessário | Sanitização na origem mascara dados pessoais e segredos nos achados; evidência truncada em 2000 caracteres | implemented | `packages/audidash-core/src/audidash_core/sanitizer.py` |
| Art. 6º, VII (segurança) | Medidas técnicas para proteger dados | Execução isolada de plugins, verificação de integridade (SHA-256), catálogo assinado (Ed25519), limites de tempo e saída | implemented | `proc.py`, `runner.py`, `manifest.py`, `catalog.py` |
| Art. 6º, VIII (prevenção) | Prevenir danos | Mascaramento antes de armazenar/exibir; plugins não confiáveis pedem confirmação; CI com SAST e varredura de segredos | implemented | `sanitizer.py`, `.github/workflows/` |
| Art. 46 (medidas de segurança) | Proteção contra acessos não autorizados e situações acidentais ou ilícitas | Sanitização na origem; autenticação forte (Argon2id + TOTP obrigatório), RBAC, mTLS entre dispositivos e servidor, CA interna com chave cifrada, rede interna, trilha de auditoria; gestão de dependências (`pip-audit`, Dependabot) | implemented | ver [mapeamento ISO 27001](iso27001-mapping.md): 5.15, 8.2, 8.3, 8.5, 8.8, 8.11, 8.15, 8.20, 8.24 |
| Art. 37 (registro das operações) | Manter registro das operações de tratamento | Trilha de auditoria no servidor, encadeada por hash e verificável (`audit verify`), com visualizador no dashboard | implemented | `packages/audidash-server/src/audidash_server/audit.py`, `packages/audidash-server/src/audidash_server/web/routes_audit.py` |
| Art. 15 e 16 (término do tratamento) | Eliminar dados após o fim da finalidade | Retenção configurável (`AUDIDASH_RETENTION_DAYS`, padrão 365 dias); `audidash-server purge` remove execuções e achados vencidos | implemented | `packages/audidash-server/src/audidash_server/services/retention.py`, `packages/audidash-server/src/audidash_server/cli.py` (`purge`) |
| Art. 48 (comunicação de incidentes) | Comunicar à ANPD e aos titulares incidente relevante | Processo/roteiro de incidente e relatório; é um processo organizacional, não código | planned | n/a |

## Limitações

- O sanitizador é baseado em padrões (regex): pode não detectar todo dado pessoal ou segredo.
  Ele cobre `title`, `evidence`, `recommendation`, `references`, `item_key`, `warnings` e
  `stderr`; o `target` de cada achado é sempre substituído pelo alvo da execução (veja
  [`SECURITY.md`](../../SECURITY.md)).
- Os achados podem conter dados sensíveis da infraestrutura auditada; trate-os conforme a
  política de segurança da sua organização.
- Veja também o [mapeamento ISO 27001/27002](iso27001-mapping.md).
