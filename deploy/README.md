# Implantação / Deployment

- [Português (BR)](#português-br)
- [English](#english)

## Português (BR)

Pilha de demonstração com Docker Compose: **PostgreSQL** (`db`), **servidor AudiDashboard**
(`server`), **Caddy** (`proxy`, TLS + mTLS) e três **alvos de laboratório** intencionalmente
vulneráveis.

### Portas

| Porta (host) | Serviço | Descrição |
|---|---|---|
| 8443 | Caddy | Dashboard web + `/ca.pem` + `/enroll`. Certificado emitido pela CA interna do AudiDashboard para `AUDIDASH_DASHBOARD_HOSTS`. `/api` e `/api/*` respondem 404. |
| 9443 | Caddy | API dos dispositivos (`/api/*` apenas), **mTLS obrigatório**. Certificado de servidor emitido pela CA interna do AudiDashboard (a CLI fixa `ca.crt`). |
| 127.0.0.1:18080 | web-noheaders | nginx sem cabeçalhos de segurança e com banner `Server: nginx/1.x`. |
| 127.0.0.1:18443 | tls-expired | nginx com certificado autoassinado **expirado** (2020-01-02). |
| 127.0.0.1:16379 | redis-open | Redis sem senha, `protected-mode no`. |

Por padrão 8443/9443 também escutam só em `127.0.0.1` (`AUDIDASH_BIND_ADDRESS`). O servidor e o
PostgreSQL não publicam portas e ficam numa rede interna sem saída para a internet.

> **Atenção:** os alvos de laboratório são **intencionalmente inseguros**. Eles ficam presos a
> `127.0.0.1`; não os exponha em outra interface nem os use fora de uma demonstração.

### Passo a passo da demo

```sh
cd deploy
cp .env.example .env
# gere um valor para cada CHANGE_ME (4 segredos):
python -c "import secrets;print(secrets.token_urlsafe(48))"
docker compose up -d --build
docker compose exec server audidash-server create-admin --username admin
docker compose exec server audidash-server show-ca-fingerprint
docker compose exec server audidash-server create-enrollment-token --created-by admin
```

O último comando imprime o token (exibido uma única vez) e o comando de inscrição. No host:

```sh
audidash enroll --server https://localhost:8443 --api https://localhost:9443 \
  --name meu-notebook --token=<TOKEN> --ca-fingerprint <SHA-256>
audidash login
audidash demo
```

- Use `--token=<TOKEN>` (com `=`): tokens podem começar com `-`.
- O dashboard abre em <https://localhost:8443>. O navegador alertará sobre a CA interna do
  AudiDashboard; para evitar o alerta, importe `ca.crt` (`docker compose cp
  server:/data/proxy/ca.crt .`) no repositório de confiança do navegador.
- `audidash enroll --ca-fingerprint` baixa `/ca.pem`, confere a impressão digital **antes** de
  enviar o token e só então o envia por TLS verificado com essa CA. O certificado da porta 8443
  é emitido para `AUDIDASH_DASHBOARD_HOSTS` (padrão `localhost,127.0.0.1`), que deve conter o
  host usado em `--server`; ele é conferido e reemitido a cada inicialização, como o da 9443.
- Os segredos do `.env` **precisam ser URL-safe** (somente `A-Z a-z 0-9 - _`, como a saída de
  `token_urlsafe`): o segredo do proxy é inserido sem escape no Caddyfile e a senha do
  PostgreSQL na URL do banco.
- O certificado da porta 9443 é emitido pela CA interna para `AUDIDASH_API_HOSTS` (padrão
  `localhost,127.0.0.1`), que deve conter o host usado em `--api`. A cada inicialização do
  `server` ele é conferido (`audidash-server check-server-cert`) e reemitido se não for da CA
  atual, se vencer em menos de 30 dias ou se os SANs diferirem de `AUDIDASH_API_HOSTS`. Depois
  de mudar a lista: `docker compose up -d --force-recreate server proxy`.
- Parar e apagar tudo (inclusive dados e a CA): `docker compose down -v`.

## English

Docker Compose demo stack: **PostgreSQL** (`db`), the **AudiDashboard server** (`server`),
**Caddy** (`proxy`, TLS + mTLS) and three intentionally vulnerable **lab targets**.

### Ports

| Host port | Service | Description |
|---|---|---|
| 8443 | Caddy | Web dashboard + `/ca.pem` + `/enroll`. Certificate issued by the AudiDashboard internal CA for `AUDIDASH_DASHBOARD_HOSTS`. `/api` and `/api/*` return 404. |
| 9443 | Caddy | Device API (`/api/*` only), **mutual TLS required**. Server certificate issued by the AudiDashboard internal CA (the CLI pins `ca.crt`). |
| 127.0.0.1:18080 | web-noheaders | nginx without security headers, `Server: nginx/1.x` banner. |
| 127.0.0.1:18443 | tls-expired | nginx with an **expired** self-signed certificate (2020-01-02). |
| 127.0.0.1:16379 | redis-open | Redis without a password, `protected-mode no`. |

8443/9443 also bind to `127.0.0.1` by default (`AUDIDASH_BIND_ADDRESS`). The server and
PostgreSQL publish no ports and sit on an internal network with no internet egress.

Caddy strips any client-supplied `X-Audidash-Proxy-Secret` / `X-Client-Cert-Fingerprint`
headers on both listeners, then sets the proxy secret, `X-Forwarded-For` (overwritten with the
TCP peer address) and, on 9443 only, the verified client certificate's SHA-256 fingerprint.

> **Warning:** the lab targets are **intentionally insecure**. They are bound to `127.0.0.1`;
> never expose them on another interface or use them outside a demo.

### Demo walkthrough

```sh
cd deploy
cp .env.example .env
# generate a value for each CHANGE_ME (4 secrets):
python -c "import secrets;print(secrets.token_urlsafe(48))"
docker compose up -d --build
docker compose exec server audidash-server create-admin --username admin
docker compose exec server audidash-server show-ca-fingerprint
docker compose exec server audidash-server create-enrollment-token --created-by admin
```

The last command prints the one-time token and the enrolment command. On the host:

```sh
audidash enroll --server https://localhost:8443 --api https://localhost:9443 \
  --name my-laptop --token=<TOKEN> --ca-fingerprint <SHA-256>
audidash login
audidash demo
```

- Pass `--token=<TOKEN>` (with `=`): tokens may start with `-`.
- The dashboard is at <https://localhost:8443>. Browsers warn about the AudiDashboard internal
  CA; to avoid it, import `ca.crt` (`docker compose cp server:/data/proxy/ca.crt .`) into the
  browser's trust store.
- `audidash enroll --ca-fingerprint` downloads `/ca.pem`, checks the fingerprint **before**
  sending the token and then sends it only over TLS verified against that CA. The 8443
  certificate is issued for `AUDIDASH_DASHBOARD_HOSTS` (default `localhost,127.0.0.1`), which
  must include the host you pass to `--server`; it is checked and reissued on every start, like
  the 9443 one.
- Secrets in `.env` **must be URL-safe** (only `A-Z a-z 0-9 - _`, as `token_urlsafe`
  produces): the proxy secret is substituted raw into the Caddyfile and the PostgreSQL
  password into the database URL.
- The 9443 certificate is issued by the internal CA for `AUDIDASH_API_HOSTS` (default
  `localhost,127.0.0.1`), which must include the host you pass to `--api`. On every `server`
  start it is checked (`audidash-server check-server-cert`) and reissued if it is not from the
  current CA, expires within 30 days, or its SANs differ from `AUDIDASH_API_HOSTS`. After
  changing the list: `docker compose up -d --force-recreate server proxy`.
- Stop and delete everything (data and CA included): `docker compose down -v`.
