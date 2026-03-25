require('dotenv').config();
const express  = require('express');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const {
  generateKeyPairSync,
  createHash,
  createSign,
  createVerify,
  constants
} = require('crypto');
const { PrismaClient } = require('@prisma/client');

const app    = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(express.static(path.join(__dirname, '../../frontend')));

function autenticar(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Token não fornecido.' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido.' });
  }
}

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ erro: 'Preencha todos os campos.' });

  const passwordHash = await bcrypt.hash(password, 10);
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  try {
    const user = await prisma.$transaction(async (tx) => {
      const u = await tx.user.create({ data: { username, email, passwordHash } });
      await tx.key.create({ data: { userId: u.id, publicKey, privateKey } });
      return u;
    });
    res.status(201).json({ mensagem: 'Usuário criado!', userId: user.id });
  } catch (err) {
    if (err.code === 'P2002')
      return res.status(409).json({ erro: 'Usuário ou e-mail já existe.' });
    res.status(500).json({ erro: 'Erro ao criar usuário.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  // Aceita email ou username no campo "email"
  const user = await prisma.user.findFirst({
    where: { OR: [{ email }, { username: email }] }
  });
  if (!user) return res.status(401).json({ erro: 'Credenciais inválidas.' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ erro: 'Credenciais inválidas.' });

  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, username: user.username });
});

app.post('/sign', autenticar, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ erro: 'Texto vazio.' });

  const chave = await prisma.key.findFirst({ where: { userId: req.usuario.id } });
  const textHash = createHash('sha256').update(text, 'utf8').digest('hex');

  const signer = createSign('RSA-SHA256');
  signer.update(text, 'utf8');
  signer.end();

  const signatureB64 = signer.sign(
    { key: chave.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
    'base64'
  );

  const sig = await prisma.signature.create({
    data: { userId: req.usuario.id, textContent: text, textHash, signatureB64 }
  });

  res.json({ id: sig.id, text, hash: textHash, signatureB64, publicKey: chave.publicKey, criadoEm: sig.createdAt });
});

app.get('/verify/:id', async (req, res) => {
  const sig = await prisma.signature.findUnique({
    where: { id: Number(req.params.id) },
    include: { user: { include: { keys: true } } }
  });
  if (!sig) return res.status(404).json({ erro: 'Não encontrada.' });

  const verifier = createVerify('RSA-SHA256');
  verifier.update(sig.textContent, 'utf8');
  verifier.end();

  const valida = verifier.verify(
    { key: sig.user.keys[0].publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
    sig.signatureB64, 'base64'
  );

  await prisma.verificationLog.create({ data: { signatureId: sig.id, result: valida } });

  res.json({
    status: valida ? 'VALIDA' : 'INVALIDA',
    signatario: sig.user.username,
    algoritmo: 'RSA-SHA256-PSS',
    text: sig.textContent,
    hash: sig.textHash,
    signatureB64: sig.signatureB64,
    publicKey: sig.user.keys[0].publicKey,
    criadoEm: sig.createdAt
  });
});

app.post('/verify', async (req, res) => {
  const { text, signatureB64, publicKey } = req.body;
  if (!text || !signatureB64 || !publicKey)
    return res.status(400).json({ erro: 'Dados obrigatórios.' });

  try {
    const verifier = createVerify('RSA-SHA256');
    verifier.update(text, 'utf8');
    verifier.end();

    const valida = verifier.verify(
      { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
      signatureB64, 'base64'
    );

    res.json({ status: valida ? 'VALIDA' : 'INVALIDA' });
  } catch (err) {
    res.status(400).json({ erro: 'Dados inválidos: verifique a chave pública e a assinatura.' });
  }
});

// Listar todas as chaves públicas
app.get('/api/keys', async (req, res) => {
  const keys = await prisma.key.findMany({
    select: { id: true, publicKey: true, userId: true, user: { select: { username: true } } }
  });
  res.json(keys);
});

// Download chave pública de qualquer usuário
app.get('/api/keys/:id/download-public', async (req, res) => {
  const chave = await prisma.key.findUnique({
    where: { id: Number(req.params.id) },
    include: { user: { select: { username: true } } }
  });
  if (!chave) return res.status(404).json({ erro: 'Não encontrada.' });
  res.setHeader('Content-Disposition', `attachment; filename=public_${chave.user.username}.pem`);
  res.setHeader('Content-Type', 'application/x-pem-file');
  res.send(chave.publicKey);
});

// Minhas chaves (para exibição no frontend)
app.get('/api/my-keys', autenticar, async (req, res) => {
  const chave = await prisma.key.findFirst({
    where: { userId: req.usuario.id },
    select: { id: true, publicKey: true }
  });
  if (!chave) return res.status(404).json({ erro: 'Não encontrada.' });
  res.json(chave);
});

// Download minha chave pública (.pem)
app.get('/api/my-keys/download-public', autenticar, async (req, res) => {
  const chave = await prisma.key.findFirst({
    where: { userId: req.usuario.id },
    include: { user: { select: { username: true } } }
  });
  if (!chave) return res.status(404).json({ erro: 'Não encontrada.' });
  res.setHeader('Content-Disposition', `attachment; filename=public_${chave.user.username}.pem`);
  res.setHeader('Content-Type', 'application/x-pem-file');
  res.send(chave.publicKey);
});

// Download minha chave privada (.pem)
app.get('/api/my-keys/download-private', autenticar, async (req, res) => {
  const chave = await prisma.key.findFirst({
    where: { userId: req.usuario.id },
    include: { user: { select: { username: true } } }
  });
  if (!chave) return res.status(404).json({ erro: 'Não encontrada.' });
  res.setHeader('Content-Disposition', `attachment; filename=private_${chave.user.username}.pem`);
  res.setHeader('Content-Type', 'application/x-pem-file');
  res.send(chave.privateKey);
});

// Download ambas as chaves (JSON)
app.get('/api/my-keys/download', autenticar, async (req, res) => {
  const chave = await prisma.key.findFirst({
    where: { userId: req.usuario.id },
    include: { user: { select: { username: true } } }
  });
  if (!chave) return res.status(404).json({ erro: 'Não encontrada.' });
  res.setHeader('Content-Disposition', `attachment; filename=keys_${chave.user.username}.json`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({ usuario: chave.user.username, publicKey: chave.publicKey, privateKey: chave.privateKey }, null, 2));
});

// Minhas assinaturas
app.get('/api/my-signatures', autenticar, async (req, res) => {
  const sigs = await prisma.signature.findMany({
    where: { userId: req.usuario.id },
    orderBy: { createdAt: 'desc' },
    select: { id: true, textContent: true, textHash: true, signatureB64: true, createdAt: true }
  });
  res.json(sigs);
});

// ── EXPORTA app para testes — só faz listen se for o entry point
module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Rodando em http://localhost:${PORT}`));
}