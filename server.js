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

/* ----------------------------- MySQL (TiDB) ----------------------------- */
const dbOptions = {
  host: process.env.DB_HOST,
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

/* ----------------------------- Mongo (Optional) ----------------------------- */
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/restaurant_board')
  .then(() => console.log("MongoDB connected"))
  .catch(() => console.log("MongoDB connection failed (ignored)"));

/* ----------------------------- Logging Schema ----------------------------- */
const activitySchema = new mongoose.Schema({
  action: String,
  user: String,
  timestamp: { type: Date, default: Date.now }
});
const Activity = mongoose.models.Activity || mongoose.model("Activity", activitySchema);

/* ----------------------------- Middlewares ----------------------------- */
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride("_method"));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 86400000 }
  })
);

/* ----------------------------- File Upload ----------------------------- */
const uploadPath = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath, { recursive: true });
const upload = multer({ dest: uploadPath });

/* ----------------------------- Resend API ----------------------------- */
const resend = new Resend(process.env.RESEND_API_KEY);
const EMAIL_FROM = process.env.EMAIL_FROM || "onboarding@resend.dev";

/* ----------------------------- AI Test Page ----------------------------- */
app.get('/ai', (req, res) => res.render("ai_test"));

/* ----------------------------- Login / Register ----------------------------- */

app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/board");
  res.render("login");
});

/* ----------------------------- 인증번호 전송 (Resend) ----------------------------- */
app.post("/send-code", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).send("이메일 없음");

    const code = Math.floor(100000 + Math.random() * 900000);
    req.session.verifyCode = code;
    req.session.verifyEmail = email;

    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: "맛집 게시판 인증번호",
      text: `인증번호는 [${code}] 입니다.`
    });

    console.log(`📧 Resend 전송 완료 → ${email} / 코드 ${code}`);
    res.send("ok");
  } catch (err) {
    console.error("Resend Error:", err);
    res.status(500).send("이메일 전송 실패");
  }
});

/* ----------------------------- Register ----------------------------- */
app.get("/register", (req, res) => res.render("register"));

app.post("/register", async (req, res) => {
  const { userid, nickname, password, email, verifyCode } = req.body;

  if (parseInt(verifyCode) !== req.session.verifyCode || email !== req.session.verifyEmail)
    return res.send(`<script>alert("인증번호가 올바르지 않습니다.");history.back();</script>`);

  const [idCheck] = await db.query(`SELECT * FROM users WHERE userid=?`, [userid]);
  if (idCheck.length > 0)
    return res.send(`<script>alert("이미 사용 중인 아이디입니다.");history.back();</script>`);

  const [nickCheck] = await db.query(`SELECT * FROM users WHERE nickname=?`, [nickname]);
  if (nickCheck.length > 0)
    return res.send(`<script>alert("닉네임이 중복입니다.");history.back();</script>`);

  await db.query(
    `INSERT INTO users (userid, nickname, password, email, profile_image, createdAt)
     VALUES (?, ?, ?, ?, NULL, NOW())`,
    [userid, nickname, password, email]
  );

  delete req.session.verifyCode;
  delete req.session.verifyEmail;

  res.send(`<script>alert("회원가입이 완료되었습니다!");location.href="/";</script>`);
});

/* ----------------------------- Login ----------------------------- */
app.post("/login", async (req, res) => {
  const { userid, password } = req.body;
  const [rows] = await db.query(
    `SELECT * FROM users WHERE userid=? AND password=?`,
    [userid, password]
  );

  if (rows.length === 0)
    return res.send(`<script>alert("아이디 또는 비밀번호 오류");history.back();</script>`);

  req.session.user = rows[0];
  req.session.save(() => res.redirect("/board"));
});

app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/")));

/* ----------------------------- 비밀번호 재설정 (Resend) ----------------------------- */
app.post("/forgot-password/send", async (req, res) => {
  const { email } = req.body;
  const [user] = await db.query(`SELECT * FROM users WHERE email=?`, [email]);

  if (user.length === 0)
    return res.send(`<script>alert("등록되지 않은 이메일입니다.");history.back();</script>`);

  const code = Math.floor(100000 + Math.random() * 900000);
  req.session.resetCode = code;
  req.session.resetEmail = email;

  await resend.emails.send({
    from: EMAIL_FROM,
    to: email,
    subject: "비밀번호 재설정",
    text: `인증번호: [${code}]`
  });

  res.send(`<script>alert("인증번호 전송 완료!");location.href="/reset-password";</script>`);
});

/* ----------------------------- Board ----------------------------- */
app.get("/board", async (req, res) => {
  if (!req.session.user) return res.redirect("/");

  const query = req.query.q || "";
  const order = req.query.order === "asc" ? "ASC" : "DESC";

  let sql = "SELECT * FROM posts";
  const params = [];

  if (query) {
    sql += " WHERE title LIKE ?";
    params.push(`%${query}%`);
  }

  sql += ` ORDER BY createdAt ${order}`;

  const [posts] = await db.query(sql, params);
  res.render("index", { posts, query, order, session: req.session });
});

/* ----------------------------- Create Post ----------------------------- */
app.get("/write", (req, res) => {
  if (!req.session.user) return res.redirect("/");
  res.render("write");
});

app.post("/write", upload.single("image"), async (req, res) => {
  const { title, content, rating, lat, lng } = req.body;
  const image = req.file ? req.file.filename : null;
  const nickname = req.session.user.nickname;

  await db.query(
    `INSERT INTO posts (title, content, rating, lat, lng, image, nickname, username, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
    [title, content, rating, lat, lng, image, nickname, nickname]
  );

  try {
    await Activity.create({ action: "게시글 작성", user: nickname });
  } catch {}

  res.redirect("/board");
});

/* ----------------------------- Setup DB ----------------------------- */
app.get("/setup-db", async (req, res) => {
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

    res.send("DB setup complete!");
  } catch (err) {
    res.send("DB Error: " + err.message);
  }
});

/* ----------------------------- Start ----------------------------- */
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
