// server.js

const express = require('express');
const session = require('express-session');
const methodOverride = require('method-override');
const multer = require('multer');
const mysql = require('mysql2/promise');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   1. MySQL (TiDB) 연결
========================= */
const dbOptions = {
  host: process.env.DB_HOST,       // Render 환경변수
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  }
};

const db = mysql.createPool(dbOptions);

/* =========================
   2. MongoDB (선택, 실패시 무시)
========================= */
mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/restaurant_board')
  .then(() => console.log('MongoDB connected'))
  .catch(() => console.log('MongoDB connection failed (ignored)'));

const activitySchema = new mongoose.Schema({
  action: String,
  user: String,
  timestamp: { type: Date, default: Date.now }
});

const Activity =
  mongoose.models.Activity || mongoose.model('Activity', activitySchema);

/* =========================
   3. 기본 설정 & 미들웨어
========================= */
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
  })
);

/* =========================
   4. 파일 업로드 설정
========================= */
const uploadPath = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
const upload = multer({ dest: uploadPath });

/* =========================
   5. Resend 이메일 설정
========================= */
const resend = new Resend(process.env.RESEND_API_KEY);
const EMAIL_FROM = process.env.EMAIL_FROM || '맛집 게시판 <onboarding@resend.dev>';

/* =========================
   6. AI 체험 페이지
========================= */
app.get('/ai', (req, res) => {
  res.render('ai_test');
});

/* =========================
   7. 로그인 / 메인
========================= */
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/board');
  res.render('login');
});

/* =========================
   8. 이메일 인증번호 전송
========================= */
app.post('/send-code', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).send('이메일 없음');

    const code = Math.floor(100000 + Math.random() * 900000);
    req.session.verifyCode = code;
    req.session.verifyEmail = email;

    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: '맛집 게시판 인증번호',
      text: `인증번호는 [${code}] 입니다.`
    });

    console.log(`📧 Resend 전송 완료 → ${email} / 코드 ${code}`);
    res.send('ok');
  } catch (err) {
    console.error('Resend Error (/send-code):', err);
    res.status(500).send('이메일 전송 실패');
  }
});

/* =========================
   9. 회원가입
========================= */
app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  try {
    const { userid, nickname, password, email, verifyCode } = req.body;

    if (
      parseInt(verifyCode) !== req.session.verifyCode ||
      email !== req.session.verifyEmail
    ) {
      return res.send(
        `<script>alert("인증번호가 올바르지 않습니다.");history.back();</script>`
      );
    }

    const [idCheck] = await db.query(
      'SELECT * FROM users WHERE userid=?',
      [userid]
    );
    if (idCheck.length > 0) {
      return res.send(
        `<script>alert("이미 사용 중인 아이디입니다.");history.back();</script>`
      );
    }

    const [nickCheck] = await db.query(
      'SELECT * FROM users WHERE nickname=?',
      [nickname]
    );
    if (nickCheck.length > 0) {
      return res.send(
        `<script>alert("닉네임이 중복입니다.");history.back();</script>`
      );
    }

    await db.query(
      `INSERT INTO users (userid, nickname, password, email, profile_image, createdAt)
       VALUES (?, ?, ?, ?, NULL, NOW())`,
      [userid, nickname, password, email]
    );

    delete req.session.verifyCode;
    delete req.session.verifyEmail;

    res.send(
      `<script>alert("회원가입이 완료되었습니다!");location.href="/";</script>`
    );
  } catch (err) {
    console.error('Register Error:', err);
    res.send(
      `<script>alert("회원가입 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   10. 로그인 / 로그아웃
========================= */
app.post('/login', async (req, res) => {
  try {
    const { userid, password } = req.body;

    const [rows] = await db.query(
      'SELECT * FROM users WHERE userid=? AND password=?',
      [userid, password]
    );

    if (rows.length === 0) {
      return res.send(
        `<script>alert("아이디 또는 비밀번호가 올바르지 않습니다.");history.back();</script>`
      );
    }

    req.session.user = rows[0];
    req.session.save(() => res.redirect('/board'));
  } catch (err) {
    console.error('Login Error:', err);
    res.send(`<script>alert("로그인 중 오류 발생");history.back();</script>`);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

/* =========================
   11. 아이디 찾기
========================= */
app.get('/find-id', (req, res) => res.render('find-id'));

app.post('/find-id/send', async (req, res) => {
  try {
    const { email } = req.body;
    const [rows] = await db.query(
      'SELECT userid FROM users WHERE email=?',
      [email]
    );

    if (rows.length === 0) {
      return res.send(
        `<script>alert("등록된 이메일 없음");history.back();</script>`
      );
    }

    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: '아이디 찾기',
      text: `아이디: [ ${rows[0].userid} ]`
    });

    res.send(
      `<script>alert("아이디 전송 완료");location.href="/";</script>`
    );
  } catch (err) {
    console.error('Find-ID Error:', err);
    res.send(
      `<script>alert("아이디 전송 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   12. 비밀번호 재설정
========================= */
app.get('/forgot-password', (req, res) =>
  res.render('forgot-password')
);

app.post('/forgot-password/send', async (req, res) => {
  try {
    const { email } = req.body;
    const [user] = await db.query(
      'SELECT * FROM users WHERE email=?',
      [email]
    );

    if (user.length === 0) {
      return res.send(
        `<script>alert("등록되지 않은 이메일입니다.");history.back();</script>`
      );
    }

    const code = Math.floor(100000 + Math.random() * 900000);
    req.session.resetCode = code;
    req.session.resetEmail = email;

    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: '비밀번호 재설정',
      text: `인증번호: [ ${code} ]`
    });

    res.send(
      `<script>alert("인증번호 전송 완료!");location.href="/reset-password";</script>`
    );
  } catch (err) {
    console.error('Forgot-Password Send Error:', err);
    res.send(
      `<script>alert("인증번호 전송 중 오류 발생");history.back();</script>`
    );
  }
});

app.get('/reset-password', (req, res) =>
  res.render('reset-password')
);

app.post('/reset-password', async (req, res) => {
  try {
    const { email, verifyCode, newPassword } = req.body;

    if (
      parseInt(verifyCode) !== req.session.resetCode ||
      email !== req.session.resetEmail
    ) {
      return res.send(
        `<script>alert("인증번호 불일치");history.back();</script>`
      );
    }

    await db.query('UPDATE users SET password=? WHERE email=?', [
      newPassword,
      email
    ]);

    delete req.session.resetCode;
    delete req.session.resetEmail;

    res.send(
      `<script>alert("비밀번호 변경 완료");location.href="/";</script>`
    );
  } catch (err) {
    console.error('Reset-Password Error:', err);
    res.send(
      `<script>alert("비밀번호 변경 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   13. 게시판 목록 (/board)
========================= */
app.get('/board', async (req, res) => {
  try {
    if (!req.session.user) return res.redirect('/');

    const sort = req.query.sort || 'date';
    const order = req.query.order === 'asc' ? 'asc' : 'desc';
    const query = req.query.q || '';

    let sql = 'SELECT * FROM posts';
    const params = [];

    if (query) {
      sql += ' WHERE title LIKE ?';
      params.push(`%${query}%`);
    }

    let orderColumn = 'createdAt';
    if (sort === 'title') orderColumn = 'title';
    if (sort === 'rating') orderColumn = 'rating';

    sql += ` ORDER BY ${orderColumn} ${order.toUpperCase()}`;

    const [posts] = await db.query(sql, params);

    res.render('index', {
      posts,
      query,
      sort,
      order,
      session: req.session
    });
  } catch (err) {
    console.error('Board Error:', err);
    res.send(
      `DB Error: ${err.message}. <br> <a href="/setup-db">👉 여기를 눌러 테이블을 생성하세요!</a>`
    );
  }
});

/* =========================
   14. 글쓰기 페이지
========================= */
app.get('/write', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.render('write');
});

/* =========================
   15. 글 작성 POST (/write)
      - lat, lng NULL 처리 포함
========================= */
app.post('/write', upload.single('image'), async (req, res) => {
  try {
    const { title, content, rating, lat, lng } = req.body;
    const image = req.file ? req.file.filename : null;
    const nickname = req.session.user?.nickname;

    if (!nickname) {
      return res.send(
        `<script>alert("로그인 세션 만료");location.href="/";</script>`
      );
    }

    const ratingNum = rating ? parseInt(rating, 10) : null;
    const latNum = lat ? parseFloat(lat) : null;
    const lngNum = lng ? parseFloat(lng) : null;

    await db.query(
      `INSERT INTO posts (title, content, rating, lat, lng, image, nickname, username, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [title, content, ratingNum, latNum, lngNum, image, nickname, nickname]
    );

    try {
      await Activity.create({ action: '게시글 작성', user: nickname });
    } catch (e) {
      console.log('Log Error (ignored):', e.message);
    }

    res.redirect('/board');
  } catch (err) {
    console.error('Write Error:', err);
    res.send(
      `<script>alert("게시글 작성 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   16. 게시글 상세 보기
========================= */
app.get('/post/:id', async (req, res) => {
  try {
    const postId = parseInt(req.params.id);
    const [rows] = await db.query(
      'SELECT * FROM posts WHERE id=?',
      [postId]
    );
    if (rows.length === 0) {
      return res.send(
        `<script>alert("게시글 없음");location.href="/board";</script>`
      );
    }

    const [comments] = await db.query(
      'SELECT * FROM comments WHERE postId=? ORDER BY createdAt DESC',
      [postId]
    );

    res.render('post', {
      post: rows[0],
      comments,
      session: req.session
    });
  } catch (err) {
    console.error('Post Detail Error:', err);
    res.send(
      `<script>alert("게시글 조회 중 오류 발생");location.href="/board";</script>`
    );
  }
});

/* =========================
   17. 댓글 작성
========================= */
app.post('/post/:id/comment', async (req, res) => {
  try {
    const postId = parseInt(req.params.id);
    const { content } = req.body;
    const nickname = req.session.user?.nickname || '익명';

    await db.query(
      'INSERT INTO comments (postId, nickname, content, createdAt) VALUES (?, ?, ?, NOW())',
      [postId, nickname, content]
    );

    try {
      await Activity.create({ action: '댓글 작성', user: nickname });
    } catch {}

    res.redirect(`/post/${postId}`);
  } catch (err) {
    console.error('Comment Write Error:', err);
    res.send(
      `<script>alert("댓글 작성 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   18. 댓글 수정 / 삭제
========================= */
app.get('/comment/:id/edit', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM comments WHERE id=?',
      [req.params.id]
    );

    if (rows.length === 0) {
      return res.send(
        `<script>alert("댓글 없음");history.back();</script>`
      );
    }

    if (rows[0].nickname !== req.session.user.nickname) {
      return res.send(
        `<script>alert("본인 댓글만 수정 가능");history.back();</script>`
      );
    }

    res.render('edit-comment', {
      comment: rows[0],
      session: req.session
    });
  } catch (err) {
    console.error('Comment Edit Page Error:', err);
    res.send(
      `<script>alert("댓글 조회 중 오류 발생");history.back();</script>`
    );
  }
});

app.post('/comment/:id', async (req, res) => {
  try {
    const { content } = req.body;
    const id = req.params.id;
    const [rows] = await db.query(
      'SELECT * FROM comments WHERE id=?',
      [id]
    );

    if (
      rows.length === 0 ||
      rows[0].nickname !== req.session.user.nickname
    ) {
      return res.redirect('/board');
    }

    await db.query('UPDATE comments SET content=? WHERE id=?', [
      content,
      id
    ]);

    res.redirect(`/post/${rows[0].postId}`);
  } catch (err) {
    console.error('Comment Update Error:', err);
    res.send(
      `<script>alert("댓글 수정 중 오류 발생");history.back();</script>`
    );
  }
});

app.post('/comment/:id/delete', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM comments WHERE id=?',
      [req.params.id]
    );

    if (
      rows.length === 0 ||
      rows[0].nickname !== req.session.user.nickname
    ) {
      return res.redirect('/board');
    }

    await db.query('DELETE FROM comments WHERE id=?', [
      req.params.id
    ]);

    res.redirect(`/post/${rows[0].postId}`);
  } catch (err) {
    console.error('Comment Delete Error:', err);
    res.send(
      `<script>alert("댓글 삭제 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   19. 게시글 수정 / 삭제
========================= */
app.get('/edit/:id', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM posts WHERE id=?',
      [req.params.id]
    );

    if (
      rows.length === 0 ||
      rows[0].nickname !== req.session.user.nickname
    ) {
      return res.redirect('/board');
    }

    res.render('edit', {
      post: rows[0],
      session: req.session
    });
  } catch (err) {
    console.error('Post Edit Page Error:', err);
    res.redirect('/board');
  }
});

app.post('/edit/:id', upload.single('image'), async (req, res) => {
  try {
    const { title, content, rating, lat, lng } = req.body;
    const image = req.file ? req.file.filename : req.body.existingImage;
    const postId = req.params.id;

    const ratingNum = rating ? parseInt(rating, 10) : null;
    const latNum = lat ? parseFloat(lat) : null;
    const lngNum = lng ? parseFloat(lng) : null;

    await db.query(
      'UPDATE posts SET title=?, content=?, rating=?, lat=?, lng=?, image=? WHERE id=?',
      [title, content, ratingNum, latNum, lngNum, image, postId]
    );

    res.redirect(`/post/${postId}`);
  } catch (err) {
    console.error('Post Update Error:', err);
    res.send(
      `<script>alert("게시글 수정 중 오류 발생");history.back();</script>`
    );
  }
});

app.post('/delete/:id', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM posts WHERE id=?',
      [req.params.id]
    );

    if (
      rows.length === 0 ||
      rows[0].nickname !== req.session.user.nickname
    ) {
      return res.redirect('/board');
    }

    await db.query('DELETE FROM posts WHERE id=?', [req.params.id]);
    res.redirect('/board');
  } catch (err) {
    console.error('Post Delete Error:', err);
    res.send(
      `<script>alert("게시글 삭제 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   20. 프로필 페이지
========================= */
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  res.render('profile', { user: req.session.user });
});

app.put('/profile', upload.single('profileImage'), async (req, res) => {
  try {
    const { nickname, newPassword } = req.body;
    const id = req.session.user.id;
    const image = req.file
      ? req.file.filename
      : req.session.user.profile_image;

    if (newPassword && newPassword.trim() !== '') {
      await db.query(
        'UPDATE users SET nickname=?, password=?, profile_image=? WHERE id=?',
        [nickname, newPassword, image, id]
      );
    } else {
      await db.query(
        'UPDATE users SET nickname=?, profile_image=? WHERE id=?',
        [nickname, image, id]
      );
    }

    const [updated] = await db.query('SELECT * FROM users WHERE id=?', [
      id
    ]);
    req.session.user = updated[0];

    req.session.save(() => {
      res.send(
        `<script>alert("프로필 변경 완료");location.href="/profile";</script>`
      );
    });
  } catch (err) {
    console.error('Profile Update Error:', err);
    res.send(
      `<script>alert("프로필 변경 중 오류 발생");history.back();</script>`
    );
  }
});

app.delete('/profile', async (req, res) => {
  try {
    if (!req.session.user) return res.redirect('/');

    await db.query('DELETE FROM users WHERE id=?', [
      req.session.user.id
    ]);

    req.session.destroy(() => {
      res.redirect('/');
    });
  } catch (err) {
    console.error('Profile Delete Error:', err);
    res.send(
      `<script>alert("회원 탈퇴 중 오류 발생");history.back();</script>`
    );
  }
});

/* =========================
   21. DB 테이블 생성용 라우트
========================= */
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

    res.send(
      '<h1>🎉 DB 테이블 생성 완료!</h1><p>이제 <a href="/">홈으로 돌아가서</a> 로그인해보세요.</p>'
    );
  } catch (err) {
    console.error('Setup-DB Error:', err);
    res.send(`DB 생성 실패: ${err.message}`);
  }
});

/* =========================
   22. 서버 시작
========================= */
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
