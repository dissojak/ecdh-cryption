# Secure Real‑Time E2E Chat (Next.js + Express + MongoDB + Socket.IO)

A full‑stack, end‑to‑end encrypted chat application with real‑time messaging, presence, JWT auth, and PIN‑based key management. Messages are encrypted client‑side and remain unreadable to the server.

## Features

- Auth: Email/password (JWT), logout, protected API routes.
- PIN & Vault:
  - First login asks for PIN to decrypt your vault.
  - Private ECDH key is encrypted with PIN (PBKDF2 + AES‑GCM).
  - PIN key cached in localStorage for 3 minutes.
  - 15‑day PIN refresh policy supported server‑side.
- End‑to‑End Encryption:
  - Per‑conversation keys via ECDH (P‑256) using WebCrypto.
  - AES‑GCM for message encryption.
  - Legacy fallback: short‑lived session key (3 min) if needed.
- Real‑Time Chat:
  - Socket.IO with JWT auth.
  - Online presence indicators.
  - Messages decrypt live when keys are available.
- Minimal UI:
  - Signup, Login, Chat pages.
  - Unlock banner prompts for PIN when needed.
  - Shows “[locked]” only when decryption is not possible.

## Architecture

- Frontend: Next.js 13+ (React, TailwindCSS)
  - Pages: `/signup`, `/login`, `/chat`
  - Crypto helpers in `client/lib/crypto.js` (PBKDF2, AES‑GCM, ECDH key derivation, local key cache)
  - API client in `client/lib/api.js` (JWT header, fetch wrapper)
- Backend: Express.js + MongoDB (Mongoose), Socket.IO
  - Auth: `/api/auth/signup`, `/api/auth/login`, `/api/auth/me`, `/api/auth/migrate-ecdh`, `/api/auth/refresh-pin`
  - Users: `/api/users` (includes `ecdhPublicJwk`)
  - Messages: `GET /api/messages/:peerId`, `POST /api/messages`
  - Presence: Socket.IO “presence” events and “chat” channel

## Security & Cryptography

- Password: bcryptjs hash (server).
- PIN:
  - Never sent back in plaintext; used client‑side to derive a key via PBKDF2 (Salted, AES‑GCM).
  - Decrypts the user’s vault which stores the private ECDH JWK.
  - Server maintains a hashed PIN for 15‑day refresh policy (no plaintext).
- E2E:
  - ECDH P‑256 per conversation (deriveKey via WebCrypto to AES‑GCM).
  - AES‑GCM payloads: `{ iv, content }` (hex/base64 per implementation).
  - Server only stores ciphertext; it cannot decrypt messages.

## Data Model

- User:
  - `username`, `email`, `passwordHash`
  - `pinHash` (for refresh policy), `encryptedVault` (PIN‑encrypted private ECDH key), `ecdhPublicJwk`
- Message:
  - `sender`, `receiver`, `encryptedContent` (JSON string), `timestamp`

## API Overview

- Auth
  - POST `/api/auth/signup` { username, email, password, pin }
  - POST `/api/auth/login` { email, password } → { token, encryptedVault, user }
  - GET `/api/auth/me` (JWT) → { user, encryptedVault }
  - POST `/api/auth/migrate-ecdh` (JWT) { pin } → updates vault with ECDH private key
  - POST `/api/auth/refresh-pin` (JWT) { oldPin, newPin }
- Users
  - GET `/api/users` (JWT) → list with `ecdhPublicJwk`
- Messages
  - GET `/api/messages/:peerId` (JWT)
  - POST `/api/messages` (JWT) { receiverId, encryptedContent }

## Realtime (Socket.IO)

- Client connects with `auth: { token }`.
- Presence: `{ userId, online }` updates.
- Chat events: server relays encrypted messages to the receiver; both sides decrypt locally.

## Run Locally

Prereqs: Node 18+, MongoDB running locally or Atlas.

1) Backend
- Create `server/.env`:
  ```
  MONGODB_URI=mongodb://localhost:27017/secure-chat
  JWT_SECRET=change-me
  ```
- Install & run:
  ```
  cd server
  npm install
  npm run dev
  ```
  Server listens on http://localhost:4000

2) Frontend
- Install & run:
  ```
  cd client
  npm install
  npm run dev
  ```
  App on http://localhost:3000 (or 3001/3002 if busy)

## Usage Flow

1. Sign up (username, email, password, PIN).
2. Log in (email, password) → receive JWT + encrypted vault.
3. Unlock with PIN → decrypts and caches private ECDH key (5 min), session key fallback (3 min).
4. Open chat, select a user:
   - Send: encrypt with per‑conversation ECDH key (AES‑GCM).
   - Receive: auto‑decrypt if keys are available; otherwise an unlock banner appears.
5. Every 3 minutes the local cache expires → prompted to re‑enter PIN.
6. Every 15 days the server enforces a PIN refresh (API supported).

## Dev & Testing

- Manual:
  - Two browsers/users, verify real‑time messages decrypt both ways.
  - Expire local cache and confirm unlock flow works.
- Automated (recommended to add):
  - Backend integration: signup/login/messages with in‑memory MongoDB.
  - Client unit tests: PBKDF2, AES‑GCM encrypt/decrypt, ECDH derivation.

## Notes

- Server never sees plaintext messages or private keys.
- Existing users auto‑migrate to ECDH on first unlock.
- If a peer has not unlocked yet, you’ll see “[locked]” until they do.

---