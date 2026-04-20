const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  transports: ['polling', 'websocket'],  // polling 먼저!
  allowUpgrades: true
});

app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());

// ─── MongoDB 연결 ───────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://kmimseo1203_db_user:d13%4012%4003%40@cluster0.bywsfcf.mongodb.net/?appName=Cluster0')
  .then(() => console.log('MongoDB 연결 완료'))
  .catch(err => console.error('MongoDB 연결 실패:', err));

// ─── 스키마 ─────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  publicKey: { type: String, default: '' },   // E2EE 공개키
  createdAt: { type: Date, default: Date.now }
});

const roomSchema = new mongoose.Schema({
  name: String,
  type: { type: String, enum: ['dm', 'group'], default: 'dm' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: 'Room', required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  senderName: String,
  // E2EE: 각 수신자별 암호화된 메시지 저장
  encryptedPayloads: [{
    userId: mongoose.Schema.Types.ObjectId,
    encryptedKey: String,    // AES 키를 수신자 공개키로 암호화
    encryptedBody: String,   // AES로 암호화된 메시지 본문
    iv: String               // AES IV
  }],
  type: { type: String, default: 'text' }, // text | file | image
  fileName: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Room = mongoose.model('Room', roomSchema);
const Message = mongoose.model('Message', messageSchema);

// ─── JWT 미들웨어 ────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '토큰 없음' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    next();
  } catch {
    res.status(401).json({ error: '유효하지 않은 토큰' });
  }
};

// ─── 인증 API ────────────────────────────────────────────────
// 회원가입
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: '이미 사용 중인 아이디예요' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user._id, username: user.username } });
  } catch (err) {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 로그인
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸어요' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸어요' });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user._id, username: user.username, publicKey: user.publicKey } });
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 공개키 업로드 (E2EE 설정)
app.post('/api/auth/publickey', auth, async (req, res) => {
  try {
    const { publicKey } = req.body;
    await User.findByIdAndUpdate(req.user.id, { publicKey });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─── 유저 API ────────────────────────────────────────────────
// 유저 검색
app.get('/api/users/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    const users = await User.find({
      username: { $regex: q, $options: 'i' },
      _id: { $ne: req.user.id }
    }).select('username publicKey').limit(10);
    res.json(users);
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

app.get('/api/rooms', auth, async (req, res) => {
  try {
    const rooms = await Room.find({ members: req.user.id })
      .populate('members', 'username publicKey')
      .sort({ createdAt: -1 });
    res.json(rooms);
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─── 채팅방 API ──────────────────────────────────────────────
// 내 채팅방 목록
app.get('/api/rooms', auth, async (req, res) => {
  try {
    const rooms = await Room.find({ members: req.user.id })
      .populate('members', 'username')
      .sort({ createdAt: -1 });
    res.json(rooms);
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 1:1 DM 채팅방 생성 or 가져오기
app.post('/api/rooms/dm', auth, async (req, res) => {
  try {
    const { targetUserId } = req.body;
    const myId = req.user.id;

    let room = await Room.findOne({
      type: 'dm',
      members: { $all: [myId, targetUserId], $size: 2 }
    }).populate('members', 'username publicKey');

    if (!room) {
      room = await Room.create({ type: 'dm', members: [myId, targetUserId] });
      room = await room.populate('members', 'username publicKey');
    }
    res.json(room);
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// 그룹 채팅방 생성
app.post('/api/rooms/group', auth, async (req, res) => {
  try {
    const { name, memberIds } = req.body;
    const members = [req.user.id, ...memberIds];
    const room = await Room.create({ type: 'group', name, members });
    const populated = await room.populate('members', 'username publicKey');
    res.json(populated);
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─── 메시지 API ──────────────────────────────────────────────
// 메시지 목록 (내 암호화된 페이로드만 반환)
app.get('/api/rooms/:roomId/messages', auth, async (req, res) => {
  try {
    const messages = await Message.find({ roomId: req.params.roomId })
      .sort({ createdAt: 1 })
      .limit(100);

    // 내 userId에 해당하는 encryptedPayload만 뽑아서 반환
    const myId = req.user.id.toString();
    const result = messages.map(m => ({
      _id: m._id,
      roomId: m.roomId,
      senderId: m.senderId,
      senderName: m.senderName,
      type: m.type,
      fileName: m.fileName,
      createdAt: m.createdAt,
      payload: m.encryptedPayloads.find(p => p.userId.toString() === myId) || null
    }));
    res.json(result);
  } catch {
    res.status(500).json({ error: '서버 오류' });
  }
});

// ─── Socket.io 실시간 통신 ───────────────────────────────────
const onlineUsers = new Map(); // userId → socketId

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('인증 필요'));
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    next();
  } catch {
    next(new Error('유효하지 않은 토큰'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  onlineUsers.set(userId, socket.id);
  console.log(`연결: ${socket.user.username} (${socket.id})`);

  // 내 채팅방들에 자동 조인
  Room.find({ members: userId }).then(rooms => {
    rooms.forEach(r => socket.join(r._id.toString()));
  });

  // 온라인 상태 브로드캐스트
  io.emit('user:online', userId);

  // 메시지 전송
  socket.on('message:send', async (data) => {
    try {
      const { roomId, encryptedPayloads, type, fileName } = data;

      // 권한 확인
      const room = await Room.findOne({ _id: roomId, members: userId });
      if (!room) return;

      const msg = await Message.create({
        roomId,
        senderId: userId,
        senderName: socket.user.username,
        encryptedPayloads,
        type: type || 'text',
        fileName
      });

      // 방 전체에 브로드캐스트 (encryptedPayloads 전체 포함)
      io.to(roomId).emit('message:new', {
        _id: msg._id,
        roomId: msg.roomId,
        senderId: userId,
        senderName: socket.user.username,
        encryptedPayloads: msg.encryptedPayloads,
        type: msg.type,
        fileName: msg.fileName,
        createdAt: msg.createdAt
      });
    } catch (err) {
      socket.emit('error', '메시지 전송 실패');
    }
  });

  // 타이핑 상태
  socket.on('typing:start', ({ roomId }) => {
    socket.to(roomId).emit('typing:start', { userId, username: socket.user.username });
  });
  socket.on('typing:stop', ({ roomId }) => {
    socket.to(roomId).emit('typing:stop', { userId });
  });

  // 연결 해제
  socket.on('disconnect', () => {
    onlineUsers.delete(userId);
    io.emit('user:offline', userId);
    console.log(`연결 해제: ${socket.user.username}`);
  });
});

// ─── 헬스체크 ────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', message: 'CloudChat API 서버 실행 중' }));

// ─── 서버 시작 ───────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`서버 실행 중: http://localhost:${PORT}`));
