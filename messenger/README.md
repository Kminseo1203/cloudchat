# 💬 메신저 배포 가이드

## 구조
```
messenger/
├── frontend/          → Cloudflare Pages (GitHub 연동)
│   ├── index.html
│   └── crypto.js
└── worker/            → Cloudflare Workers (백엔드 + 실시간)
    ├── src/
    │   ├── index.js   (API 라우터)
    │   └── chatroom.js (WebSocket Durable Object)
    ├── schema.sql     (D1 데이터베이스)
    ├── wrangler.toml
    └── package.json
```

---

## 1단계 — GitHub 레포 만들기

```bash
git init
git add .
git commit -m "first commit"
git remote add origin https://github.com/너의아이디/messenger.git
git push -u origin main
```

---

## 2단계 — Cloudflare 가입
https://dash.cloudflare.com → 무료 가입 (카드 없음)

---

## 3단계 — Worker 배포

```bash
cd worker
npm install

# Cloudflare 로그인
npx wrangler login

# D1 데이터베이스 생성
npx wrangler d1 create messenger-db
# → 출력된 database_id를 wrangler.toml에 붙여넣기

# DB 스키마 적용
npx wrangler d1 execute messenger-db --file=schema.sql

# 환경변수 설정
npx wrangler secret put JWT_SECRET
# → 입력: 랜덤 긴 문자열 (예: openssl rand -hex 32 로 생성)

npx wrangler secret put FRONTEND_URL
# → 입력: https://your-project.pages.dev (4단계 후 알 수 있음)

npx wrangler secret put WORKER_URL
# → 입력: https://messenger-worker.YOUR-SUBDOMAIN.workers.dev

npx wrangler secret put GOOGLE_CLIENT_ID
# → Google Cloud Console에서 발급한 Client ID

npx wrangler secret put GOOGLE_CLIENT_SECRET
# → Google Cloud Console에서 발급한 Client Secret

# Worker 배포
npx wrangler deploy
```

### Google Cloud Console 설정 (무료)
1. https://console.cloud.google.com 접속
2. 새 프로젝트 생성
3. **APIs & Services → OAuth consent screen** → External 선택 → 앱 이름 입력
4. **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
   - Application type: **Web application**
   - Authorized redirect URIs: `https://messenger-worker.YOUR-SUBDOMAIN.workers.dev/api/auth/google/callback`
5. Client ID, Client Secret 복사 → wrangler secret에 입력

---

## 4단계 — Pages 배포 (프론트엔드)

1. Cloudflare 대시보드 → Workers & Pages → Create → Pages
2. Connect to Git → GitHub 연결 → messenger 레포 선택
3. 설정:
   - **Framework preset**: None
   - **Build command**: (비워두기)
   - **Build output directory**: `frontend`
4. Deploy!
5. → `https://your-project.pages.dev` URL 생성됨

---

## 5단계 — API URL 연결

`frontend/index.html` 3번째 줄 수정:
```javascript
const API = 'https://messenger-worker.YOUR-SUBDOMAIN.workers.dev';
```

수정 후 git push → Pages 자동 재배포됨

---

## 6단계 — FRONTEND_URL 업데이트

```bash
cd worker
npx wrangler secret put FRONTEND_URL
# → https://your-project.pages.dev 입력
npx wrangler deploy
```

---

## 완성!

| | URL |
|--|--|
| 프론트엔드 | https://your-project.pages.dev |
| 백엔드 API | https://messenger-worker.YOUR-SUBDOMAIN.workers.dev |

- ✅ 무료, 카드 없음
- ✅ 슬립 없음 (Cloudflare는 항상 켜짐)
- ✅ E2EE 암호화
- ✅ 실시간 WebSocket
- ✅ GitHub push → 자동 배포
