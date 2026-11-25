# SOC AudiDashboard — Design

> Data: 2026-11-25 · Status: rascunho para aprovação
> Projeto **estudantil** e open source (Apache-2.0), feito para portfólio.

## 1. Intenção e porquê

Equipes de TI/SI de uma empresa mantêm dezenas de scripts de auditoria espalhados (Bash, PowerShell, Python), executados à mão contra servidores locais, datacenters, nuvem (IaaS) e SaaS. O resultado fica em arquivos soltos, sem visão consolidada.

O SOC AudiDashboard reúne esses scripts num **único aplicativo**:

- o analista executa as auditorias a partir da própria máquina;
- os achados são padronizados, classificados por severidade e enviados de forma segura a um servidor central;
- um **dashboard web** mostra para a equipe o nível de ameaça, as suspeitas de comprometimento, as tendências e as recomendações.

Por ser projeto de portfólio, a qualidade de engenharia é visível e faz parte do produto: segurança por design, testes, CI, versionamento, documentação e alinhamento com ISO 27001/27002 e LGPD.

## 2. Objetivos, não-objetivos e anti-objetivos

**Objetivos**
- Catálogo extensível de scripts de auditoria em qualquer linguagem (Python, PowerShell, Bash), com código sempre consultável no app e no repositório.
- Formato único de achados (findings), com severidade, evidência, recomendação e referências (CIS / ISO 27002).
- Nota de ameaça de 0 a 100 por ativo e global, com destaque para **suspeitas**, isto é, indícios de comprometimento e não só de má configuração.
- Conexão cliente↔servidor sem expor dados: mTLS, minimização e sanitização na origem.
- Ambiente de demonstração subindo com `docker compose up`, incluindo alvos de laboratório propositalmente inseguros.

**Não-objetivos (v1)**
- Agentes residentes instalados nos alvos.
- Execução agendada/centralizada no servidor (fica como evolução futura).
- Remediação automática: o sistema recomenda, mas não altera os alvos.
- Certificação ISO formal. O projeto *se alinha* a controles; não é certificado.
- SSO/OIDC (planejado para a v2).

**Anti-objetivos (fracasso mesmo que funcione)**
- O servidor central virar um cofre com as credenciais da empresa.
- Um plugin de terceiros executar sem que o usuário possa ver o código e sem verificação de integridade.
- Dados pessoais ou segredos (senhas, tokens, chaves) chegarem ao servidor ou aos logs.
- Ser usado contra alvos sem autorização. O README e o app exibem aviso de uso ético e autorizado.

## 3. Restrições

- Python 3.12+; gerenciador `uv` com workspace monorepo.
- Precisa rodar em Windows, Linux e macOS (app desktop).
- Tudo open source e reproduzível localmente, sem depender de serviço pago.
- Código, commits e docstrings em inglês; README e docs em PT-BR e EN.

## 4. Abordagens consideradas

| Decisão | Opções | Escolha e porquê |
|---|---|---|
| Onde executa | **A)** máquina do analista, servidor só guarda resultados · **B)** servidor executa com cofre central | **A**: menor privilégio, sem ponto único com todas as credenciais, mais simples de subir |
| Forma do cliente | **1)** desktop PySide6 + dashboard web · 2) agente local + tudo no navegador · 3) CLI + web | **1**: "aplicativo" real, sem porta local aberta, separa quem executa de quem acompanha |
| Plugins | a) só Python + SDK · **b)** qualquer linguagem + manifesto + saída JSON | **b**: aproveita o acervo existente das equipes (PS/Bash) |
| Dashboard | **FastAPI + HTMX** · FastAPI + React · Dash/Streamlit | **HTMX**: majoritariamente Python, renderizado no servidor, CSP rígida viável |
| Login | **Local + MFA (TOTP), SSO depois** · só SSO · ambos | Local + MFA: seguro e fácil de testar |
| Licença | **Apache-2.0** · MIT · AGPL | Apache-2.0: permissiva, com cláusula de patentes |

## 5. Arquitetura

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

### Pacotes do monorepo
```
packages/
  audidash-core/      # schema de manifesto e findings (pydantic), runner, sanitizer, scoring, cliente HTTP
  audidash-desktop/   # app PySide6
  audidash-server/    # FastAPI (API + dashboard), SQLAlchemy 2, Alembic
  audidash-sdk/       # SDK opcional para plugins Python
plugins/              # catálogo oficial (um diretório por plugin)
lab/                  # alvos de laboratório inseguros (containers) para demo e testes de integração
deploy/               # docker-compose, config do proxy, scripts de CA
docs/                 # arquitetura, segurança, conformidade, guia de plugins (PT/EN)
```

## 6. Modelo de plugins

Cada plugin é um diretório:
```
plugins/linux-ssh-hardening/
  plugin.yaml
  run.py | run.ps1 | run.sh
  README.md
  tests/   # fixtures de saída esperada
```

**`plugin.yaml`** (validado por schema):
- `id`, `name`, `version` (SemVer), `author`, `license`, `description`
- `runtime`: `python` | `powershell` | `bash`
- `entrypoint`, `sha256` de cada arquivo executável
- `targets`: tipos suportados (`linux`, `windows`, `aws`, `azure`, `gcp`, `m365`, `network`, `web`, `local`)
- `connection`: `ssh` | `winrm` | `cloud-api` | `network` | `local`
- `permissions`: declaração legível (por exemplo, "lê /etc/ssh/sshd_config", "chama iam:ListUsers") exibida antes da execução
- `references`: controles CIS / ISO 27002 cobertos
- `trust`: definido pelo **catálogo**, nunca pelo autor: `official` | `verified` | `community`

**Execução (runner)**
- O app verifica o hash e, para `official`/`verified`, a assinatura Ed25519 do catálogo (minisign/PyNaCl). Divergência bloqueia a execução.
- Plugins `community` exigem confirmação explícita após a exibição do código.
- Executa em subprocesso com ambiente limpo, diretório temporário, timeout configurável e sem herdar variáveis sensíveis do app.
- Entrada: JSON via **stdin** (alvo, parâmetros e credenciais efêmeras resolvidas do keyring). Credenciais nunca vão em argv nem em variáveis de ambiente.
- Saída: JSON via stdout, validado contra o schema de findings. Saída inválida vira erro de execução, não achado.

**Schema de finding**
```json
{ "id": "SSH-001", "title": "...", "severity": "info|low|medium|high|critical",
  "category": "misconfiguration|vulnerability|suspicious|compliance",
  "target": "srv01", "evidence": "...", "recommendation": "...",
  "references": ["CIS 5.2.10", "ISO27002:2022 8.5"] }
```

## 7. Nota de ameaça

- Peso por severidade: info 0, baixa 1, média 3, alta 7, crítica 10. Achados `suspicious` recebem multiplicador ×1,5.
- Criticidade do ativo (definida no inventário): baixa 0,5 · média 1,0 · alta 1,5.
- Nota do ativo = `100 × (1 − e^(−Σ peso × criticidade / k))`, com k = 20 configurável. A escala satura e nunca passa de 100.
- Nota global = média das notas dos ativos, ponderada pela criticidade.
- Faixas: 0–24 Baixo · 25–49 Moderado · 50–74 Alto · 75–100 Crítico.
- Achados têm ciclo de vida (aberto → reconhecido → resolvido / falso positivo / risco aceito, com justificativa obrigatória). Só os abertos e reconhecidos contam na nota.

## 8. Segurança da comunicação e dos dados

**Transporte**
- TLS 1.3 obrigatório; HSTS no dashboard.
- **mTLS** entre app e API: cada dispositivo passa por um *enrollment* com token de uso único gerado por um admin no dashboard. O app gera o par de chaves localmente e envia um CSR; a CA interna assina um certificado com validade curta (90 dias, renovável). O dispositivo pode ser revogado no dashboard.
- Além do certificado, o usuário do app faz login (senha + TOTP) e recebe um token de acesso curto (15 min) vinculado ao certificado.

**Dashboard web**
- Senhas com Argon2id; MFA TOTP obrigatório; bloqueio progressivo e rate limiting no login.
- Cookies de sessão `HttpOnly`, `Secure`, `SameSite=Strict`; token CSRF; CSP sem `unsafe-inline`; cabeçalhos de segurança.
- RBAC: `admin` (usuários, dispositivos, catálogo), `analyst` (executa e trata achados), `viewer` (somente leitura, por exemplo, para gestores).

**Dados (LGPD / minimização)**
- O sanitizer roda **no cliente, antes do envio**: remove padrões de segredos (chaves privadas, tokens AWS/Azure, senhas em strings de conexão) e mascara PII (CPF, e-mail, telefone). A evidência é truncada a um tamanho máximo.
- Retenção configurável (padrão de 365 dias para achados, com expurgo automático).
- Log de auditoria append-only com encadeamento de hash (quem executou, o quê, quando, de qual dispositivo).
- Segredos do servidor via Docker secrets / variáveis de ambiente, nunca no repositório.

## 9. Catálogo de plugins (ondas)

Baseado em CIS Benchmarks, CIS Controls v8 e ISO 27002:2022.

**Onda 1 (v0.1)**
- Linux: hardening SSH; contas UID 0 / sem senha / sudoers; atualizações pendentes; serviços e portas escutando; permissões de arquivos sensíveis; firewall (ufw/nftables)
- Windows: política de senha e bloqueio; administradores locais; Defender e firewall; atualizações pendentes; SMBv1 / RDP NLA
- Rede: varredura de portas TCP; certificado TLS (validade, versão, cifras fracas)
- Web: cabeçalhos de segurança HTTP
- Exemplos em PowerShell e em Bash provando o modelo multilinguagem

**Onda 2**
- AWS: S3 públicos; IAM sem MFA / chaves antigas; root com uso recente; security groups 0.0.0.0/0; CloudTrail desabilitado; EBS/RDS sem criptografia
- Azure: contas sem MFA; storage público; NSGs abertos; Defender for Cloud
- GCP: buckets públicos; contas de serviço com chaves; regras de firewall abertas

**Onda 3: suspeitas / indícios de comprometimento**
- Linux: contas criadas recentemente; cron/systemd persistente desconhecido; binários SUID incomuns; authorized_keys alterado; falhas de login em massa (auth.log)
- Windows: tarefas agendadas e serviços suspeitos; chaves Run; eventos 4625/4720/4732; contas admin novas
- Processos com conexões de saída para portas incomuns

**Onda 4**
- Microsoft 365 / Entra ID: MFA, regras de encaminhamento externo, apps OAuth com permissões amplas
- Active Directory: senhas que nunca expiram, contas inativas, Kerberoasting (SPNs em contas de usuário), membros de Domain Admins
- Docker/Kubernetes: containers privilegiados, socket exposto, imagens `latest`
- DNS/e-mail: SPF, DKIM, DMARC
- Bancos de dados: portas expostas, autenticação fraca

## 10. Processo de desenvolvimento

- **Ágil**: GitHub Projects (kanban), issues com templates, sprints de 2 semanas mapeadas às ondas e milestones por versão.
- **Versionamento**: SemVer, Conventional Commits, CHANGELOG gerado, tags e releases no GitHub, GitHub Flow com proteção da branch `main`.
- **CI (GitHub Actions)**: ruff (lint e formatação), mypy, pytest com cobertura, bandit, pip-audit, gitleaks, CodeQL, Dependabot, validação de todos os `plugin.yaml` e verificação de hash/assinatura do catálogo.
- **Comunidade**: README PT/EN (com aviso de projeto estudantil e de uso ético), CONTRIBUTING, guia de criação de plugins, CODE_OF_CONDUCT, SECURITY.md (divulgação responsável), templates de PR.
- **Conformidade**: `docs/compliance/` mapeia os controles do produto para o Anexo A da ISO 27001:2022 e para os artigos da LGPD (6º princípios, 46 segurança, 37 registro de operações).

## 11. Interface (diretrizes)

- **Dashboard**: tema escuro por padrão, com tema claro disponível. Página inicial com o medidor de nota global, cards por severidade, lista de suspeitas em destaque, ativos mais críticos, tendência no tempo e conformidade por controle. Telas de ativos, achados (com filtros e ciclo de vida), execuções, catálogo de plugins com visualizador de código, dispositivos, usuários e log de auditoria. Gráficos com Chart.js servido localmente (sem CDN).
- **App desktop**: navegação lateral (Catálogo, Alvos, Executar, Resultados, Configurações). O visualizador de código tem syntax highlighting. A execução mostra progresso por plugin e alvo, e os resultados podem ser revisados antes de enviar.

## 12. Decisões tomadas na revisão (chamadas do Claude, revisáveis)

1. **Onde o código do plugin roda.** Dois modos, declarados no manifesto por `execution`:
   - `remote`: scripts Bash/PowerShell são enviados ao alvo pelo stdin da sessão SSH/WinRM e executam **no alvo**, sem gravar em disco. O JSON volta pela mesma sessão. Assim os scripts que as equipes já têm funcionam como estão, e Bash não precisa existir na máquina Windows do analista. Quem mantém as conexões é o core.
   - `local`: o plugin roda na máquina do analista, em subprocesso isolado. É o caso de nuvem/API, rede e web (tipicamente Python via SDK, que recebe as credenciais efêmeras por stdin).
2. **Escopo do plano.** O plano de implementação cobre a **v0.1** (core, servidor, desktop, mTLS/CA, plugins da onda 1, lab, CI e docs). Cada onda seguinte terá plano próprio.
3. **Ativos e identidade dos achados.**
   - O **registro de ativos fica no servidor** e é compartilhado pela equipe: nome, endereço, tipo, criticidade e tags, nada sensível. O app sincroniza essa lista; as credenciais continuam só no keyring local.
   - "srv01" é um único ativo, não importa quem o audite.
   - Identidade do achado: impressão digital = `plugin_id + finding.id + asset_id (+ chave opcional do item, ex. nome do usuário)`. Quando o mesmo achado aparece numa nova execução, ele é atualizado (`last_seen`), não duplicado.
   - Quando a execução seguinte do mesmo plugin no mesmo ativo **não reporta mais** o achado, ele é resolvido automaticamente (`auto-resolved`), com registro no histórico. Estados manuais (risco aceito / falso positivo) não são alterados automaticamente.
   - Achados sem nova verificação há mais de 90 dias aparecem como "desatualizados" e continuam contando na nota, para incentivar reauditoria.
4. **Distribuição e confiança do catálogo.**
   - `official`: plugins do repositório, empacotados com o app e assinados com a chave Ed25519 do projeto. A chave fica offline com o mantenedor; o CI apenas **verifica** as assinaturas.
   - `verified`: plugins aprovados pelo admin da organização no dashboard. O servidor publica uma allowlist de hashes, que o app sincroniza por mTLS.
   - `community`: qualquer plugin importado localmente pelo analista. Exige revisão do código e confirmação a cada nova versão.
5. **Windows no laboratório.** No CI, os plugins Windows são testados com saídas gravadas (fixtures) e com PowerShell 7 em container Linux nas partes portáveis. Um Vagrantfile/roteiro opcional sobe uma VM Windows Server de avaliação para a demo completa (Hyper-V disponível no Windows 11 Pro).
6. **Certificado por dispositivo.** O certificado identifica a **máquina**; o login (senha + TOTP) identifica a **pessoa**. O token de acesso carrega os dois, e o log de auditoria registra usuário e dispositivo. Vários usuários podem usar a mesma máquina, e uma pessoa pode ter várias máquinas. A revogação é por dispositivo e, separadamente, por usuário.

## 13. Decisões deixadas ao construtor

- Escolha do reverse proxy (nginx ou Caddy) e a forma de repassar a identidade do certificado à API.
- Bibliotecas de conexão (asyncssh vs paramiko; pywinrm/pypsrp).
- Estrutura interna de módulos, nomes de tabelas e migrações.
- Layout visual detalhado das telas, dentro das diretrizes da seção 11.
- Empacotamento do app desktop (PyInstaller ou Briefcase).
