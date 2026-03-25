const request = require('supertest');
const app     = require('../src/server');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

let token;
let signatureId;

beforeAll(async () => {
  await prisma.verificationLog.deleteMany({});
  await prisma.signature.deleteMany({});
  await prisma.key.deleteMany({ where: { user: { email: 'teste@teste.com' } } });
  await prisma.user.deleteMany({ where: { email: 'teste@teste.com' } });

  await request(app).post('/register').send({
    username: 'usuarioteste',
    email:    'teste@teste.com',
    password: '123456'
  });

  const res = await request(app).post('/login').send({
    email: 'teste@teste.com', password: '123456'
  });
  token = res.body.token;
});

afterAll(async () => {
  await prisma.verificationLog.deleteMany({});
  await prisma.signature.deleteMany({});
  await prisma.key.deleteMany({ where: { user: { email: 'teste@teste.com' } } });
  await prisma.user.deleteMany({ where: { email: 'teste@teste.com' } });
  await prisma.$disconnect();
});

// TESTE 1 — POSITIVO
test('Assinatura original deve retornar VALIDA', async () => {
  const signRes = await request(app)
    .post('/sign')
    .set('Authorization', `Bearer ${token}`)
    .send({ text: 'Documento de teste para assinatura digital.' });

  expect(signRes.status).toBe(200);
  signatureId = signRes.body.id;

  const verifyRes = await request(app).get(`/verify/${signatureId}`);
  expect(verifyRes.body.status).toBe('VALIDA');
});

// TESTE 2 — NEGATIVO
test('Assinatura corrompida deve retornar INVALIDA', async () => {
  await prisma.signature.update({
    where: { id: signatureId },
    data:  { signatureB64: 'assinatura_falsa_invalida==' }
  });

  const verifyRes = await request(app).get(`/verify/${signatureId}`);
  expect(verifyRes.body.status).toBe('INVALIDA');
});
