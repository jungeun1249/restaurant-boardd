const request = require('supertest');
const express = require('express');
const session = require('express-session');

const app = express();
app.use(session({ secret: 'test', resave: false, saveUninitialized: false }));

app.get('/', (req, res) => {
  res.status(200).send('Login Page');
});

describe('서버 라우팅 테스트', () => {
  test('GET / (메인 진입) 요청 시 200 OK 반환', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
  });
});