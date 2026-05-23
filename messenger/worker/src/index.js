import { ChatRoom } from './chatroom.js';

export { ChatRoom };

// ─── JWT 헬퍼 ─────────────────────────────────────────────
async function signJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBin = Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBin, new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

async function hashPassword(pw) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

// ─── CORS 헤더 ────────────────────────────────────────────
function cors(env) {
  return {
    'Access-Control-Allow-Origin': env.FRONTEND_URL || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  };
}

function json(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors(env) }
  });
}

// ─── 인증 미들웨어 ────────────────────────────────────────
async function authenticate(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return verifyJWT(token, env.JWT_SECRET);
}

// ─── 라우터 ───────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // OPTIONS (CORS preflight)
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors(env) });
    }

    // ── Google OAuth 시작 → Google 로그인 페이지로 리다이렉트 ──
    if (path === '/api/auth/google' && method === 'GET') {
      const params = new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        redirect_uri: `${env.WORKER_URL}/api/auth/google/callback`,
        response_type: 'code',
        scope: 'openid email profile',
        prompt: 'select_account'
      });
      return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`, 302);
    }

    // ── Google OAuth 콜백 ──
    if (path === '/api/auth/google/callback' && method === 'GET') {
      const code = url.searchParams.get('code');
      if (!code) return Response.redirect(`${env.FRONTEND_URL}?error=no_code`, 302);

      // code → access_token 교환
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: `${env.WORKER_URL}/api/auth/google/callback`,
          grant_type: 'authorization_code'
        })
      });
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) return Response.redirect(`${env.FRONTEND_URL}?error=token_fail`, 302);

      // Google 유저 정보 가져오기
      const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const profile = await profileRes.json();
      const googleId = profile.id;
      const email = profile.email;
      const username = profile.name?.replace(/\s+/g, '_') || email.split('@')[0];

      // DB에서 유저 찾거나 생성
      let user = await env.DB.prepare('SELECT * FROM users WHERE google_id = ?').bind(googleId).first();
      if (!user) {
        // 아이디 중복 처리
        let finalUsername = username;
        const dup = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
        if (dup) finalUsername = `${username}_${googleId.slice(-4)}`;

        const id = crypto.randomUUID();
        await env.DB.prepare(
          'INSERT INTO users (id, username, password, google_id, email) VALUES (?, ?, ?, ?, ?)'
        ).bind(id, finalUsername, '', googleId, email).run();
        user = { id, username: finalUsername };
      }

      // JWT 발급
      const jwt = await signJWT(
        { id: user.id, username: user.username, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 },
        env.JWT_SECRET
      );

      // 프론트엔드로 리다이렉트 (token + user 쿼리스트링)
      const userData = encodeURIComponent(JSON.stringify({ id: user.id, username: user.username }));
      return Response.redirect(`${env.FRONTEND_URL}?token=${jwt}&user=${userData}`, 302);
    }

    // ── 회원가입 ──
    if (path === '/api/auth/register' && method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password || password.length < 8)
        return json({ error: '아이디 입력 & 비밀번호 8자 이상' }, 400, env);

      const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (exists) return json({ error: '이미 사용 중인 아이디예요' }, 400, env);

      const hashed = await hashPassword(password);
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO users (id, username, password) VALUES (?, ?, ?)')
        .bind(id, username, hashed).run();

      const token = await signJWT(
        { id, username, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 },
        env.JWT_SECRET
      );
      return json({ token, user: { id, username } }, 200, env);
    }

    // ── 로그인 ──
    if (path === '/api/auth/login' && method === 'POST') {
      const { username, password } = await request.json();
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) return json({ error: '아이디 또는 비밀번호가 틀렸어요' }, 400, env);

      const hashed = await hashPassword(password);
      if (user.password !== hashed) return json({ error: '아이디 또는 비밀번호가 틀렸어요' }, 400, env);

      const token = await signJWT(
        { id: user.id, username: user.username, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7 },
        env.JWT_SECRET
      );
      return json({ token, user: { id: user.id, username: user.username, publicKey: user.public_key } }, 200, env);
    }

    // ── 공개키 업로드 ──
    if (path === '/api/auth/publickey' && method === 'POST') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: '인증 필요' }, 401, env);
      const { publicKey } = await request.json();
      await env.DB.prepare('UPDATE users SET public_key = ? WHERE id = ?').bind(publicKey, user.id).run();
      return json({ success: true }, 200, env);
    }

    // ── 유저 검색 ──
    if (path === '/api/users/search' && method === 'GET') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: '인증 필요' }, 401, env);
      const q = url.searchParams.get('q') || '';
      const users = await env.DB.prepare(
        "SELECT id, username, public_key FROM users WHERE username LIKE ? AND id != ? LIMIT 10"
      ).bind(`%${q}%`, user.id).all();
      return json(users.results.map(u => ({ _id: u.id, username: u.username, publicKey: u.public_key })), 200, env);
    }

    // ── 채팅방 목록 ──
    if (path === '/api/rooms' && method === 'GET') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: '인증 필요' }, 401, env);
      const rooms = await env.DB.prepare(`
        SELECT r.id, r.name, r.type FROM rooms r
        JOIN room_members rm ON r.id = rm.room_id
        WHERE rm.user_id = ? ORDER BY r.created_at DESC
      `).bind(user.id).all();

      const result = await Promise.all(rooms.results.map(async r => {
        const members = await env.DB.prepare(`
          SELECT u.id, u.username, u.public_key FROM users u
          JOIN room_members rm ON u.id = rm.user_id WHERE rm.room_id = ?
        `).bind(r.id).all();
        return {
          _id: r.id, name: r.name, type: r.type,
          members: members.results.map(m => ({ _id: m.id, username: m.username, publicKey: m.public_key }))
        };
      }));
      return json(result, 200, env);
    }

    // ── DM 채팅방 생성/가져오기 ──
    if (path === '/api/rooms/dm' && method === 'POST') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: '인증 필요' }, 401, env);
      const { targetUserId } = await request.json();

      // 기존 DM 방 찾기
      const existing = await env.DB.prepare(`
        SELECT r.id FROM rooms r
        JOIN room_members rm1 ON r.id = rm1.room_id AND rm1.user_id = ?
        JOIN room_members rm2 ON r.id = rm2.room_id AND rm2.user_id = ?
        WHERE r.type = 'dm' LIMIT 1
      `).bind(user.id, targetUserId).first();

      let roomId = existing?.id;
      if (!roomId) {
        roomId = crypto.randomUUID();
        await env.DB.prepare('INSERT INTO rooms (id, type) VALUES (?, ?)').bind(roomId, 'dm').run();
        await env.DB.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').bind(roomId, user.id).run();
        await env.DB.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').bind(roomId, targetUserId).run();
      }

      const members = await env.DB.prepare(`
        SELECT u.id, u.username, u.public_key FROM users u
        JOIN room_members rm ON u.id = rm.user_id WHERE rm.room_id = ?
      `).bind(roomId).all();

      return json({
        _id: roomId, type: 'dm',
        members: members.results.map(m => ({ _id: m.id, username: m.username, publicKey: m.public_key }))
      }, 200, env);
    }

    // ── 그룹 채팅방 생성 ──
    if (path === '/api/rooms/group' && method === 'POST') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: '인증 필요' }, 401, env);
      const { name, memberIds } = await request.json();
      const roomId = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO rooms (id, name, type) VALUES (?, ?, ?)').bind(roomId, name, 'group').run();
      const allMembers = [user.id, ...memberIds];
      await Promise.all(allMembers.map(uid =>
        env.DB.prepare('INSERT INTO room_members (room_id, user_id) VALUES (?, ?)').bind(roomId, uid).run()
      ));
      const members = await env.DB.prepare(`
        SELECT u.id, u.username, u.public_key FROM users u
        JOIN room_members rm ON u.id = rm.user_id WHERE rm.room_id = ?
      `).bind(roomId).all();
      return json({
        _id: roomId, name, type: 'group',
        members: members.results.map(m => ({ _id: m.id, username: m.username, publicKey: m.public_key }))
      }, 200, env);
    }

    // ── 메시지 목록 ──
    if (path.startsWith('/api/rooms/') && path.endsWith('/messages') && method === 'GET') {
      const user = await authenticate(request, env);
      if (!user) return json({ error: '인증 필요' }, 401, env);
      const roomId = path.split('/')[3];
      const msgs = await env.DB.prepare(`
        SELECT m.id, m.room_id, m.sender_id, m.sender_name, m.type, m.file_name, m.created_at,
               mp.encrypted_key, mp.encrypted_body, mp.iv
        FROM messages m
        LEFT JOIN message_payloads mp ON m.id = mp.message_id AND mp.user_id = ?
        WHERE m.room_id = ? ORDER BY m.created_at ASC LIMIT 100
      `).bind(user.id, roomId).all();

      return json(msgs.results.map(m => ({
        _id: m.id, roomId: m.room_id, senderId: m.sender_id,
        senderName: m.sender_name, type: m.type, fileName: m.file_name, createdAt: m.created_at,
        payload: m.encrypted_key ? { encryptedKey: m.encrypted_key, encryptedBody: m.encrypted_body, iv: m.iv } : null
      })), 200, env);
    }

    // ── WebSocket (Durable Object로 위임) ──
    if (path === '/ws') {
      const user = await authenticate(request, env);
      if (!user) return new Response('인증 필요', { status: 401 });

      // 글로벌 ChatRoom Durable Object 사용
      const id = env.CHAT_ROOM.idFromName('global');
      const stub = env.CHAT_ROOM.get(id);
      const newReq = new Request(request.url, {
        headers: { ...Object.fromEntries(request.headers), 'X-User-Id': user.id, 'X-Username': user.username },
        method: request.method
      });
      return stub.fetch(newReq);
    }

    return json({ error: '없는 경로예요' }, 404, env);
  }
};
