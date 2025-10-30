const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'supersecretkey';
const db = new sqlite3.Database('./db.sqlite');

// Инициализация таблиц
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    avatar TEXT,
    bio TEXT,
    postsCount INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sectionId INTEGER,
    title TEXT,
    authorId INTEGER,
    createdAt INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threadId INTEGER,
    authorId INTEGER,
    text TEXT,
    createdAt INTEGER
  )`);
});

// Регистрация
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users(username,password) VALUES(?,?)', [username, hash], function(err){
    if(err) return res.status(400).json({error: 'Имя уже занято'});
    const token = jwt.sign({id:this.lastID}, SECRET);
    res.json({token});
  });
});

// Вход
app.post('/api/login', (req, res)=>{
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username=?', [username], (err,user)=>{
    if(!user) return res.status(400).json({error:'Пользователь не найден'});
    if(!bcrypt.compareSync(password,user.password)) return res.status(400).json({error:'Неверный пароль'});
    const token = jwt.sign({id:user.id}, SECRET);
    res.json({token, user});
  });
});

// Middleware авторизации
function auth(req,res,next){
  const token = req.headers.authorization?.split(' ')[1];
  if(!token) return res.status(401).json({error:'Нет токена'});
  try{
    const data = jwt.verify(token, SECRET);
    req.userId = data.id;
    next();
  } catch { res.status(401).json({error:'Неверный токен'}); }
}

// Получить разделы
app.get('/api/sections', (req,res)=>{
  db.all('SELECT * FROM sections', [], (err, rows)=>{
    res.json(rows);
  });
});

// Создать раздел
app.post('/api/sections', auth, (req,res)=>{
  const { name } = req.body;
  db.run('INSERT INTO sections(name) VALUES(?)', [name], function(err){
    res.json({id:this.lastID,name});
  });
});

// Получить темы раздела
app.get('/api/threads/:sectionId', (req,res)=>{
  const { sectionId } = req.params;
  db.all('SELECT threads.*, users.username FROM threads JOIN users ON threads.authorId = users.id WHERE sectionId=?', [sectionId], (err,rows)=>{
    res.json(rows);
  });
});

// Создать тему
app.post('/api/threads', auth, (req,res)=>{
  const { sectionId, title } = req.body;
  const createdAt = Date.now();
  db.run('INSERT INTO threads(sectionId,title,authorId,createdAt) VALUES(?,?,?,?)', [sectionId,title,req.userId,createdAt], function(err){
    res.json({id:this.lastID,sectionId,title,authorId:req.userId,createdAt});
  });
});

// Получить посты темы
app.get('/api/posts/:threadId', (req,res)=>{
  const { threadId } = req.params;
  db.all('SELECT posts.*, users.username FROM posts JOIN users ON posts.authorId=users.id WHERE threadId=? ORDER BY createdAt ASC', [threadId], (err,rows)=>{
    res.json(rows);
  });
});

// Создать пост
app.post('/api/posts', auth, (req,res)=>{
  const { threadId, text } = req.body;
  const createdAt = Date.now();
  db.run('INSERT INTO posts(threadId,authorId,text,createdAt) VALUES(?,?,?,?)', [threadId, req.userId, text, createdAt], function(err){
    res.json({id:this.lastID, threadId, authorId:req.userId, text, createdAt});
  });
});

app.listen(3000,()=>console.log('Server running on http://localhost:3000'));
