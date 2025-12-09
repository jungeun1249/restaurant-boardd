const express = require('express');
const session = require('express-session');
const methodOverride = require('method-override');
const multer = require('multer');
const mysql = require('mysql2/promise');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

const dbOptions = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '1234',
  database: process.env.DB_NAME || 'restaurant_board',
  port: process.env.DB_PORT || 4000,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: false
  }
};

const db = mysql.createPool(dbOptions);

const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/restaurant_board';

mongoose.connect(mongoURI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.log('⚠️ MongoDB connection failed (Logging disabled)');
  });

const activitySchema = new mongoose.Schema({
  action: String,
  user: String,
  timestamp: { type: Date, default: Date.now }
});

const Activity = mongoose.models.Activity || mongoose.model('Activity', activitySchema);

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const uploadPath = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
const upload = multer({ dest: uploadPath });

app.get('/ai', (req, res) => {
  res.render('ai_test');
});

app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/board');
  res.render('login');
});

app.post('/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('이메일이 필요합니다.');

  const code = Math.floor(100000 + Math.random() * 900000);
  req.session.verifyCode = code;
  req.session.verifyEmail = email;

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: 'wnsrms1249@gmail.com',
      pass: 'wlrqrztcoftqqdzc'
    },
    tls: { rejectUnauthorized: false }
  });

  try {
    await transporter.sendMail({
      from: '맛집 게시판 <wnsrms1249@gmail.com>',
      to: email,
      subject: '맛집 게시판 인증번호',
      text: `인증번호는 [${code}] 입니다.`
    });
    console.log(`📧 인증번호 ${code} → ${email}`);
    res.send('ok');
  } catch (err) {
    console.error(err);
    res.status(500).send('이메일 전송 실패');
  }
});

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  const { userid, nickname, password, email, verifyCode } = req.body;

  if (req.session.verifyCode !== parseInt(verifyCode) || req.session.verifyEmail !== email) {
    return res.send('<script>alert("인증번호가 올바르지 않습니다.");history.back();</script>');
  }

  const [idCheck] = await db.query('SELECT * FROM users WHERE userid=?', [userid]);
  if (idCheck.length > 0) return res.send('<script>alert("이미 사용 중인 아이디입니다.");history.back();</script>');

  const [nickCheck] = await db.query('SELECT * FROM users WHERE nickname=?', [nickname]);
  if (nickCheck.length > 0) return res.send('<script>alert("닉네임이 중복입니다.");history.back();</script>');

  await db.query(
    'INSERT INTO users (userid, nickname, password, email, profile_image, createdAt) VALUES (?, ?, ?, ?, NULL, NOW())',
    [userid, nickname, password, email]
  );

  delete req.session.verifyCode;
  delete req.session.verifyEmail;

  res.send('<script>alert("회원가입이 완료되었습니다!");location.href="/";</script>');
});

app.post('/login', async (req, res) => {
  const { userid, password } = req.body;
  const [rows] = await db.query('SELECT * FROM users WHERE userid=? AND password=?', [userid, password]);
  
  if (rows.length > 0) {
    req.session.user = rows[0];
    req.session.save(() => {
        res.redirect('/board');
    });
  } else {
    res.send('<script>alert("아이디 또는 비밀번호가 올바르지 않습니다.");history.back();</script>');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/forgot-password', (req, res) => res.render('forgot-password'));

app.post('/forgot-password/send', async (req, res) => {
  const { email } = req.body;
  const [user] = await db.query('SELECT * FROM users WHERE email=?', [email]);
  
  if (user.length === 0) {
    return res.send('<script>alert("등록되지 않은 이메일입니다.");history.back();</script>');
  }

  const code = Math.floor(100000 + Math.random() * 900000);
  req.session.resetCode = code;
  req.session.resetEmail = email;

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: 'wnsrms1249@gmail.com',
      pass: 'wlrqrztcoftqqdzc'
    },
    tls: { rejectUnauthorized: false }
  });

  await transporter.sendMail({
    from: '맛집 게시판',
    to: email,
    subject: '비밀번호 재설정',
    text: `인증번호: [ ${code} ]`
  });

  res.send('<script>alert("인증번호 전송 완료!");location.href="/reset-password";</script>');
});

app.get('/reset-password', (req, res) => res.render('reset-password'));

app.post('/reset-password', async (req, res) => {
  const { email, verifyCode, newPassword } = req.body;
  
  if (req.session.resetCode !== parseInt(verifyCode) || req.session.resetEmail !== email) {
    return res.send('<script>alert("인증번호 불일치");history.back();</script>');
  }
  
  await db.query('UPDATE users SET password=? WHERE email=?', [newPassword, email]);
  delete req.session.resetCode;
  delete req.session.resetEmail;
  
  res.send('<script>alert("비밀번호 변경 완료");location.href="/";</script>');
});

app.get('/find-id', (req, res) => res.render('find-id'));

app.post('/find-id/send', async (req, res) => {
  const { email } = req.body;
  const [rows] = await db.query('SELECT userid FROM users WHERE email=?', [email]);
  
  if (rows.length === 0) {
    return res.send('<script>alert("등록된 이메일 없음");history.back();</script>');
  }
  
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
      user: 'wnsrms1249@gmail.com',
      pass: 'wlrqrztcoftqqdzc'
    },
    tls: { rejectUnauthorized: false }
  });
  
  await transporter.sendMail({
    from: '맛집 게시판',
    to: email,
    subject: '아이디 찾기',
    text: `아이디: [ ${rows[0].userid} ]`
  });
  
  res.send('<script>alert("아이디 전송 완료");location.href="/";</script>');
});

app.get('/board', async (req, res) => {
  if (!req.session.user) return res.redirect('/');

  const sort = req.query.sort || 'date';
  const order = req.query.order === 'asc' ? 'ASC' : 'DESC';
  const query = req.query.q || '';

  let sql = 'SELECT * FROM posts';
  const params = [];

  if (query) {
    sql += ' WHERE title LIKE ?';
    params.push(`%${query}%`);
  }
  sql += ` ORDER BY createdAt ${order}`;

  try {
      const [posts] = await db.query(sql, params);
      res.render('index', { 
          posts, 
          sort, 
          order: order.toLowerCase(), 
          query, 
          session: req.session 
      });
  } catch (err) {
      res.send(`DB Error: ${err.message}. <br> <a href="/setup-db">👉 여기를 눌러 테이블을 생성하세요!</a>`);
  }
});

app.get('/write', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.render('write');
});

app.post('/write', upload.single('image'), async (req, res) => {
  const { title, content, rating, lat, lng } = req.body;
  const image = req.file ? req.file.filename : null;
  const nickname = req.session.user?.nickname;

  await db.query(
    'INSERT INTO posts (title, content, rating, lat, lng, image, nickname, username, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())',
    [title, content, rating, lat, lng, image, nickname, nickname]
  );

  try {
      await Activity.create({ action: '게시글 작성', user: nickname });
  } catch (e) {}

  res.redirect('/board');
});

app.get('/post/:id', async (req, res) => {
  const postId = parseInt(req.params.id);
  const [rows] = await db.query('SELECT * FROM posts WHERE id = ?', [postId]);
    
  if (rows.length === 0) {
      return res.send('<script>alert("게시글 없음");location.href="/board";</script>');
  }
    
  const [comments] = await db.query('SELECT * FROM comments WHERE postId = ? ORDER BY createdAt DESC', [postId]);
    
  res.render('post', { post: rows[0], comments, session: req.session });
});

app.post('/post/:id/comment', async (req,  
res) => {
  const postId = req.params.id;
  const { content } = req.body;
  const nickname = req.session.user?.nickname || '익명';
    
  await db.query('INSERT INTO comments (postId, nickname, content, createdAt) VALUES (?, ?, ?, NOW())', [postId, nickname, content]);
    
  try { 
      await Activity.create({ action: '댓글 작성', user: nickname }); 
  } catch (e) {}
    
  res.redirect(`/post/${postId}`);
});

app.get('/comment/:id/edit', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM comments WHERE id=?', [req.params.id]);
    
  if (rows.length === 0) {
      return res.send('<script>alert("댓글 없음");history.back();</script>');
  }
    
  if (rows[0].nickname !== req.session.user.nickname) {
      return res.send('<script>alert("본인 댓글만 수정 가능");history.back();</script>');
  }
    
  res.render('edit-comment', { comment: rows[0], session: req.session });
});

app.post('/comment/:id', async (req, res) => {
  const { content } = req.body;
  const id = req.params.id;
    
  const [rows] = await db.query('SELECT * FROM comments WHERE id=?', [id]);
  if (rows.length === 0 || rows[0].nickname !== req.session.user.nickname)
    return res.redirect('/board');
    
  await db.query('UPDATE comments SET content=? WHERE id=?', [content, id]);
  res.redirect(`/post/${rows[0].postId}`);
});

app.post('/comment/:id/delete', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM comments WHERE id=?', [req.params.id]);
    
  if (rows.length === 0 || rows[0].nickname !== req.session.user.nickname)
    return res.redirect('/board');

  await db.query('DELETE FROM comments WHERE id=?', [req.params.id]);
  res.redirect(`/post/${rows[0].postId}`);
});

app.get('/edit/:id', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM posts WHERE id=?', [req.params.id]);
    
  if (rows.length === 0 || rows[0].nickname !== req.session.user.nickname)
    return res.redirect('/board');

  res.render('edit', { post: rows[0], session: req.session });
});

app.post('/edit/:id', upload.single('image'), async (req, res) => {
  const { title, content, rating, lat, lng } = req.body;
  const image = req.file ? req.file.filename : req.body.existingImage;
  const postId = req.params.id;
    
  await db.query('UPDATE posts SET title=?, content=?, rating=?, lat=?, lng=?, image=? WHERE id=?', [title, content, rating, lat, lng, image, postId]);
  res.redirect(`/post/${postId}`);
});

app.post('/delete/:id', async (req, res) => {
  const [rows] = await db.query('SELECT * FROM posts WHERE id=?', [req.params.id]);
    
  if (rows.length === 0 || rows[0].nickname !== req.session.user.nickname)
    return res.redirect('/board');

  await db.query('DELETE FROM posts WHERE id=?', [req.params.id]);
  res.redirect('/board');
});

app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.render('profile', { user: req.session.user });
});

app.put('/profile', upload.single('profileImage'), async (req, res) => {
  const { nickname, newPassword } = req.body;
  const id = req.session.user.id;
  const image = req.file ? req.file.filename : req.session.user.profile_image;
    
  if (newPassword && newPassword.trim() !== '') {
    await db.query('UPDATE users SET nickname=?, password=?, profile_image=? WHERE id=?', [nickname, newPassword, image, id]);
  } else {
    await db.query('UPDATE users SET nickname=?, profile_image=? WHERE id=?', [nickname, image, id]);
  }
    
  const [updated] = await db.query('SELECT * FROM users WHERE id=?', [id]);
  req.session.user = updated[0];
    
  req.session.save(() => {
    res.send('<script>alert("프로필 변경 완료");location.href="/profile";</script>');
  });
});

app.delete('/profile', async (req, res) => {
  if (!req.session.user) return res.redirect('/');
    
  await db.query('DELETE FROM users WHERE id=?', [req.session.user.id]);
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/setup-db', async (req, res) => {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userid VARCHAR(255) NOT NULL UNIQUE,
        nickname VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        profile_image VARCHAR(255),
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        rating INT,
        lat DOUBLE,
        lng DOUBLE,
        image VARCHAR(255),
        nickname VARCHAR(255),
        username VARCHAR(255),
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        postId INT NOT NULL,
        nickname VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (postId) REFERENCES posts(id) ON DELETE CASCADE
      )
    `);

    res.send('<h1>🎉 DB 테이블 생성 완료!</h1><p>이제 <a href="/">홈으로 돌아가서</a> 로그인해보세요.</p>');
  } catch (err) {
    res.send(`DB 생성 실패: ${err.message}`);
  }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
