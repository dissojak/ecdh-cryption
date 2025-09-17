import express from 'express';
import mongoose from 'mongoose';
import crypto from 'crypto';
import cors from 'cors';
import http from 'http';
import { Server as SocketIO } from 'socket.io';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

export const app = express();
app.use(express.json());
app.use(cors({ origin: [/^http:\/\/localhost:\d+$/], credentials: true }));
export const server = http.createServer(app);
export const io = new SocketIO(server, { cors: { origin: [/^http:\/\/localhost:\d+$/] } });

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-chat';
await mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const EncryptedBlobSchema = new mongoose.Schema({
  encrypted: String,
  salt: String,
  iv: String,
  tag: String,
}, { _id: false });

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  pinHash: { type: String, required: true },
  encryptedVault: { type: EncryptedBlobSchema, required: true },
  ecdhPublicJwk: { type: mongoose.Schema.Types.Mixed },
  pinLastRefreshedAt: { type: Date, default: Date.now },
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedContent: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

export const User = mongoose.model('User', userSchema);
export const Message = mongoose.model('Message', messageSchema);

function encryptVaultKey(vaultPayload, pin) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(pin, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const input = Buffer.isBuffer(vaultPayload) ? vaultPayload : Buffer.from(vaultPayload);
  let encrypted = cipher.update(input, undefined, 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag();
  return {
    encrypted,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Auth: Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, pin } = req.body;
    if (!username || !email || !password || !pin) return res.status(400).json({ error: 'Missing fields' });
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ error: 'User already exists' });
    const passwordHash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);
    // Generate ECDH keypair (P-256)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecdhPublicJwk = publicKey.export({ format: 'jwk' });
    const ecdhPrivateJwk = privateKey.export({ format: 'jwk' });
    // Prepare vault payload containing private key (as JSON string)
    const vaultPayload = JSON.stringify({ version: 1, ecdhPrivateJwk });
    const encryptedVault = encryptVaultKey(vaultPayload, pin);
    await User.create({ username, email, passwordHash, pinHash, encryptedVault, ecdhPublicJwk, pinLastRefreshedAt: new Date() });
    return res.json({ success: true });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Signup failed' });
  }
});

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    const fifteenDaysMs = 15 * 24 * 60 * 60 * 1000;
    const pinRefreshRequired = !user.pinLastRefreshedAt || (Date.now() - new Date(user.pinLastRefreshedAt).getTime()) > fifteenDaysMs;
    return res.json({ token, user: { id: user._id, username: user.username, email: user.email }, encryptedVault: user.encryptedVault, pinRefreshRequired });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// Auth: Refresh PIN backup (verifies PIN and updates timestamp)
app.post('/api/auth/refresh-pin', authMiddleware, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'Missing PIN' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const ok = await bcrypt.compare(pin, user.pinHash);
    if (!ok) return res.status(400).json({ error: 'Invalid PIN' });
    user.pinLastRefreshedAt = new Date();
    await user.save();
    return res.json({ success: true });
  } catch (e) {
    console.error('Refresh PIN error:', e);
    return res.status(500).json({ error: 'Failed to refresh PIN' });
  }
});

// Users list
app.get('/api/users', authMiddleware, async (req, res) => {
  const raw = await User.find({}, '_id username ecdhPublicJwk');
  const users = raw.map(u => ({ id: u._id, username: u.username, ecdhPublicJwk: u.ecdhPublicJwk }));
  return res.json({ users });
});

// Current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  return res.json({ user: { id: user._id, username: user.username, email: user.email, ecdhPublicJwk: user.ecdhPublicJwk }, encryptedVault: user.encryptedVault });
});

// Migrate existing accounts to ECDH vault using provided PIN
app.post('/api/auth/migrate-ecdh', authMiddleware, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'Missing PIN' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.ecdhPublicJwk) return res.json({ success: true, alreadyMigrated: true });
    const ok = await bcrypt.compare(pin, user.pinHash);
    if (!ok) return res.status(400).json({ error: 'Invalid PIN' });
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecdhPublicJwk = publicKey.export({ format: 'jwk' });
    const ecdhPrivateJwk = privateKey.export({ format: 'jwk' });
    const vaultPayload = JSON.stringify({ version: 1, ecdhPrivateJwk });
    const encryptedVault = encryptVaultKey(vaultPayload, pin);
    user.ecdhPublicJwk = ecdhPublicJwk;
    user.encryptedVault = encryptedVault;
    user.pinLastRefreshedAt = new Date();
    await user.save();
    return res.json({ success: true });
  } catch (e) {
    console.error('Migrate ECDH error:', e);
    return res.status(500).json({ error: 'Migration failed' });
  }
});

// Send message
app.post('/api/messages', authMiddleware, async (req, res) => {
  const { receiverId, encryptedContent } = req.body;
  if (!receiverId || !encryptedContent) return res.status(400).json({ error: 'Missing fields' });
  const message = new Message({ sender: req.userId, receiver: receiverId, encryptedContent });
  await message.save();
  // Emit via socket
  io.to(receiverId.toString()).emit('chat', { sender: req.userId, receiver: receiverId, encryptedContent, timestamp: message.timestamp });
  io.to(req.userId.toString()).emit('chat', { sender: req.userId, receiver: receiverId, encryptedContent, timestamp: message.timestamp });
  res.json({ success: true });
});

// Get conversation
app.get('/api/messages/:peerId', authMiddleware, async (req, res) => {
  const { peerId } = req.params;
  const messages = await Message.find({
    $or: [
      { sender: req.userId, receiver: peerId },
      { sender: peerId, receiver: req.userId },
    ],
  }).sort({ timestamp: 1 });
  res.json({ messages });
});

// Presence tracking
const onlineUsers = new Map(); // userId -> Set(socketIds)

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // eslint-disable-next-line no-param-reassign
    socket.userId = payload.sub;
  } catch {}
  next();
});

io.on('connection', (socket) => {
  if (socket.userId) {
    const set = onlineUsers.get(socket.userId) || new Set();
    set.add(socket.id);
    onlineUsers.set(socket.userId, set);
    socket.join(socket.userId); // room per user
    io.emit('presence', { userId: socket.userId, online: true });
  }

  socket.on('disconnect', () => {
    if (socket.userId) {
      const set = onlineUsers.get(socket.userId);
      if (set) {
        set.delete(socket.id);
        if (set.size === 0) {
          onlineUsers.delete(socket.userId);
          io.emit('presence', { userId: socket.userId, online: false });
        } else {
          onlineUsers.set(socket.userId, set);
        }
      }
    }
  });
});

export default app;
