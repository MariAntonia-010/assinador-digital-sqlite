# Assinador Digital Web

Aplicação web de assinatura digital com RSA-SHA256-PSS, persistência em SQLite e interface completa de verificação.

## Como rodar

```bash
cd backend
npm install
npx prisma migrate dev --name init
npm start
# Acesse http://localhost:3000
```

O banco será criado em: `backend/prisma/banco.db`

## Fluxo da aplicação

1. **Cadastro** (`/`) → gera par de chaves RSA-2048, armazena no banco
2. **Login** → retorna JWT (válido por 8h)
3. **Assinar** (`/sign.html`) → digita texto, backend calcula SHA-256 + assina com chave privada, persiste e retorna ID
4. **Verificar** (`/verify.html`) → por ID ou manualmente (texto + assinatura + chave pública)
5. **Chaves** (`/keys.html`) → lista chaves públicas de todos, download das próprias chaves

## Endpoints

| Método | Rota                            | Auth | Descrição                                          |
|--------|---------------------------------|------|----------------------------------------------------|
| POST   | /register                       | Não  | Cria usuário e gera par de chaves RSA              |
| POST   | /login                          | Não  | Autentica e retorna JWT                            |
| POST   | /sign                           | JWT  | Assina texto, persiste e retorna ID                |
| GET    | /verify/:id                     | Não  | Verifica assinatura por ID                         |
| POST   | /verify                         | Não  | Verifica manualmente (texto + assinatura + chave)  |
| GET    | /api/keys                       | Não  | Lista todas as chaves públicas                     |
| GET    | /api/keys/:id/download-public   | Não  | Download chave pública (.pem) de qualquer usuário  |
| GET    | /api/my-keys                    | JWT  | Retorna chave pública do usuário logado            |
| GET    | /api/my-keys/download-public    | JWT  | Download minha chave pública (.pem)                |
| GET    | /api/my-keys/download-private   | JWT  | Download minha chave privada (.pem)                |
| GET    | /api/my-keys/download           | JWT  | Download ambas as chaves (.json)                   |
| GET    | /api/my-signatures              | JWT  | Lista assinaturas do usuário logado                |

## Exemplos de requisição/resposta

**POST /register**
```json
// Request
{ "username": "joao", "email": "joao@email.com", "password": "123456" }
// Response 201
{ "mensagem": "Usuário criado!", "userId": 1 }
```

**POST /login**
```json
// Request
{ "email": "joao@email.com", "password": "123456" }
// Response 200
{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "username": "joao" }
```

**POST /sign** *(Authorization: Bearer \<token\>)*
```json
// Request
{ "text": "Eu, João, declaro que li e aceito o contrato." }
// Response 200
{
  "id": 1,
  "text": "Eu, João, declaro que li e aceito o contrato.",
  "hash": "a3f1c2...",
  "signatureB64": "MEUCIQDx...",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "criadoEm": "2026-03-24T19:00:00.000Z"
}
```

**GET /verify/1**
```json
// Response 200
{
  "status": "VALIDA",
  "signatario": "joao",
  "algoritmo": "RSA-SHA256-PSS",
  "text": "Eu, João, declaro que li e aceito o contrato.",
  "hash": "a3f1c2...",
  "signatureB64": "MEUCIQDx...",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "criadoEm": "2026-03-24T19:00:00.000Z"
}
```

**POST /verify** *(verificação manual)*
```json
// Request
{ "text": "...", "signatureB64": "...", "publicKey": "-----BEGIN PUBLIC KEY-----\n..." }
// Response 200
{ "status": "VALIDA" }
```

## Testes

```bash
cd backend && npm test
```

Casos cobertos:
- ✅ **Positivo** — assina um texto e verifica: espera `VALIDA`
- ❌ **Negativo** — corrompe a assinatura no banco e verifica: espera `INVALIDA`

## Banco de dados

**Schema:** `backend/prisma/schema.prisma`
**Migrações:** `backend/prisma/migrations/`
**Arquivo SQLite:** `backend/prisma/banco.db`

Para gerar dump SQL:
```bash
cd backend/prisma
sqlite3 banco.db .dump > dump.sql
```

Modelos:
- `User` — id, username, email, passwordHash
- `Key` — id, userId, publicKey, privateKey
- `Signature` — id, userId, textContent, textHash, signatureB64, createdAt
- `VerificationLog` — id, signatureId, result, verifiedAt

## Algoritmo

- **Par de chaves:** RSA-2048, formato SPKI/PKCS8 PEM
- **Assinatura:** RSA-SHA256-PSS (`RSA_PKCS1_PSS_PADDING`, `saltLength = digestLength`)
- **Hash do texto:** SHA-256 (hex), calculado separadamente para exibição
- **Autenticação:** JWT HS256, expira em 8h

## Autores
- Maria Antônia
- Isaias
