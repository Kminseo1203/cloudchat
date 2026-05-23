// Cloudflare Durable Object — 실시간 WebSocket 핸들러
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map(); // userId → WebSocket
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader !== 'websocket') {
      return new Response('WebSocket 업그레이드 필요', { status: 426 });
    }

    const userId = request.headers.get('X-User-Id');
    const username = request.headers.get('X-Username');

    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    // 세션 등록
    this.sessions.set(userId, { ws: server, username });

    // 온라인 유저 목록 전송
    server.send(JSON.stringify({
      type: 'online_users',
      userIds: [...this.sessions.keys()]
    }));

    // 다른 유저에게 온라인 알림
    this.broadcast({ type: 'user_online', userId }, userId);

    server.addEventListener('message', async (event) => {
      try {
        const data = JSON.parse(event.data);
        await this.handleMessage(userId, username, data);
      } catch (err) {
        server.send(JSON.stringify({ type: 'error', message: '잘못된 메시지 형식' }));
      }
    });

    server.addEventListener('close', () => {
      this.sessions.delete(userId);
      this.broadcast({ type: 'user_offline', userId });
    });

    server.addEventListener('error', () => {
      this.sessions.delete(userId);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  async handleMessage(userId, username, data) {
    switch (data.type) {

      // 메시지 전송
      case 'message:send': {
        const { roomId, encryptedPayloads, type, fileName } = data;
        const msgId = crypto.randomUUID();
        const createdAt = new Date().toISOString();

        // D1에 메시지 저장
        await this.env.DB.prepare(
          'INSERT INTO messages (id, room_id, sender_id, sender_name, type, file_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(msgId, roomId, userId, username, type || 'text', fileName || null, createdAt).run();

        // 각 수신자별 암호화 페이로드 저장
        await Promise.all((encryptedPayloads || []).map(p =>
          this.env.DB.prepare(
            'INSERT INTO message_payloads (message_id, user_id, encrypted_key, encrypted_body, iv) VALUES (?, ?, ?, ?, ?)'
          ).bind(msgId, p.userId, p.encryptedKey, p.encryptedBody, p.iv).run()
        ));

        // 방 멤버들에게 브로드캐스트
        const members = await this.env.DB.prepare(
          'SELECT user_id FROM room_members WHERE room_id = ?'
        ).bind(roomId).all();

        const msg = {
          type: 'message:new',
          _id: msgId,
          roomId,
          senderId: userId,
          senderName: username,
          msgType: type || 'text',
          fileName,
          encryptedPayloads,
          createdAt
        };

        members.results.forEach(({ user_id }) => {
          const session = this.sessions.get(user_id);
          if (session) {
            try { session.ws.send(JSON.stringify(msg)); } catch {}
          }
        });
        break;
      }

      // 타이핑 상태
      case 'typing:start':
      case 'typing:stop': {
        const { roomId } = data;
        const members = await this.env.DB.prepare(
          'SELECT user_id FROM room_members WHERE room_id = ?'
        ).bind(roomId).all();
        members.results.forEach(({ user_id }) => {
          if (user_id === userId) return;
          const session = this.sessions.get(user_id);
          if (session) {
            try { session.ws.send(JSON.stringify({ type: data.type, userId, username, roomId })); } catch {}
          }
        });
        break;
      }
    }
  }

  broadcast(msg, excludeUserId = null) {
    const text = JSON.stringify(msg);
    this.sessions.forEach(({ ws }, uid) => {
      if (uid === excludeUserId) return;
      try { ws.send(text); } catch {}
    });
  }
}
