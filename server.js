import express from 'express';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';
import { randomUUID } from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'data', 'db.json');
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || 'change-me-in-production';

const app = express();
const server = http.createServer(app);

const wss = new WebSocketServer({ server, path: '/' });
const clients = new Map();

function ensureDbFile() {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(dbPath)) {
    const initial = {
      users: [],
      conversations: [],
      messages: [],
    };
    fs.writeFileSync(dbPath, JSON.stringify(initial, null, 2));
  }
}

function readDb() {
  ensureDbFile();
  return JSON.parse(fs.readFileSync(dbPath, 'utf8'));
}

function writeDb(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

function sanitizeUser(user) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    username: user.username,
    avatar: user.avatar,
    createdAt: user.createdAt,
  };
}

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, jwtSecret, { expiresIn: '7d' });
}

function getUserById(userId) {
  const db = readDb();
  return db.users.find(user => user.id === userId) || null;
}

function getUserByEmail(email) {
  const db = readDb();
  return db.users.find(user => user.email.toLowerCase() === String(email).toLowerCase()) || null;
}

function hashValue(value) {
  return bcrypt.hashSync(value, 10);
}

function getConversationById(conversationId) {
  const db = readDb();
  return db.conversations.find(conversation => conversation.id === conversationId) || null;
}

function normalizeUsername(value, fallback = 'user') {
  const clean = String(value || fallback)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
    .trim();

  return clean || fallback;
}

function ensureUniqueUsername(base) {
  const db = readDb();
  let username = normalizeUsername(base, 'user');
  let count = 1;
  while (db.users.some(user => user.username === username)) {
    username = `${normalizeUsername(base, 'user')}${count}`;
    count += 1;
  }
  return username;
}

function toConversationView(conversation, userId) {
  const db = readDb();
  const participants = conversation.participants || [];
  const lastMessage = db.messages
    .filter(m => m.conversationId === conversation.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];

  return {
    id: conversation.id,
    name: conversation.name || 'Conversation',
    participants,
    members: db.users.filter(user => participants.includes(user.id)).map(sanitizeUser),
    lastMessage: lastMessage ? lastMessage.text : 'No messages yet',
    lastMessageAt: lastMessage ? lastMessage.createdAt : null,
    unreadCount: 0,
    online: participants.some(id => id !== userId && clients.has(id)),
  };
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, jwtSecret);
    const user = getUserById(decoded.sub);
    if (!user) return res.status(401).json({ message: 'Invalid session' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'nexus' });
});

app.post('/api/auth/register', (req, res) => {
  const { displayName, email, password } = req.body || {};

  if (!displayName || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  const db = readDb();
  if (db.users.some(user => user.email.toLowerCase() === String(email).trim().toLowerCase())) {
    return res.status(409).json({ message: 'Email already in use' });
  }

  const user = {
    id: randomUUID(),
    email: String(email).trim().toLowerCase(),
    displayName: String(displayName).trim(),
    username: ensureUniqueUsername(displayName),
    avatar: String(displayName).trim().charAt(0).toUpperCase() || 'N',
    passwordHash: hashValue(password),
    createdAt: new Date().toISOString(),
  };

  db.users.push(user);
  writeDb(db);

  const token = signToken(user);
  return res.status(201).json({ token, user: sanitizeUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const user = getUserByEmail(email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const valid = bcrypt.compareSync(password, user.passwordHash);
  if (!valid) return res.status(401).json({ message: 'Invalid credentials' });

  const token = signToken(user);
  return res.json({ token, user: sanitizeUser(user) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: sanitizeUser(req.user) });
});

app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const db = readDb();
  if (!q) return res.json({ users: [] });

  const results = db.users
    .filter(user => {
      const haystack = `${user.displayName} ${user.username} ${user.email}`.toLowerCase();
      return haystack.includes(q);
    })
    .filter(user => user.id !== req.user.id)
    .slice(0, 12)
    .map(sanitizeUser);

  return res.json({ users: results });
});

app.get('/api/conversations', authMiddleware, (req, res) => {
  const db = readDb();
  const userId = req.user.id;
  const conversations = db.conversations
    .filter(conversation => (conversation.participants || []).includes(userId))
    .map(conversation => toConversationView(conversation, userId));

  conversations.sort((a, b) => new Date(b.lastMessageAt || 0) - new Date(a.lastMessageAt || 0));
  return res.json({ conversations });
});

app.post('/api/conversations', authMiddleware, (req, res) => {
  const { participantIds = [] } = req.body || {};
  const db = readDb();
  const normalized = [...new Set([req.user.id, ...participantIds.filter(Boolean)])];
  if (normalized.length < 2) {
    return res.status(400).json({ message: 'At least one participant is required' });
  }

  let conversation = db.conversations.find(item => {
    const participants = item.participants || [];
    return participants.length === normalized.length && normalized.every(id => participants.includes(id));
  });

  if (!conversation) {
    conversation = {
      id: randomUUID(),
      name: 'Conversation',
      participants: normalized,
      createdAt: new Date().toISOString(),
    };
    db.conversations.push(conversation);
    writeDb(db);
  }

  return res.status(201).json({ conversation: toConversationView(conversation, req.user.id) });
});

app.get('/api/conversations/:id/messages', authMiddleware, (req, res) => {
  const conversationId = req.params.id;
  const db = readDb();
  const conversation = getConversationById(conversationId);
  if (!conversation) return res.status(404).json({ message: 'Conversation not found' });
  if (!(conversation.participants || []).includes(req.user.id)) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  const messages = db.messages
    .filter(message => message.conversationId === conversationId)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

  return res.json({ messages });
});

app.post('/api/conversations/:id/messages', authMiddleware, (req, res) => {
  const conversationId = req.params.id;
  const { text } = req.body || {};
  const db = readDb();
  const conversation = getConversationById(conversationId);
  if (!conversation) return res.status(404).json({ message: 'Conversation not found' });
  if (!(conversation.participants || []).includes(req.user.id)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  if (!String(text || '').trim()) {
    return res.status(400).json({ message: 'Message text is required' });
  }

  const message = {
    id: randomUUID(),
    conversationId,
    senderId: req.user.id,
    text: String(text).trim(),
    createdAt: new Date().toISOString(),
    status: 'sent',
  };

  db.messages.push(message);
  writeDb(db);

  const payload = {
    type: 'message:new',
    message,
  };

  for (const participantId of conversation.participants || []) {
    if (participantId === req.user.id) continue;
    broadcastToUser(participantId, payload);
  }

  return res.status(201).json({ message });
});

function broadcastToUser(userId, payload) {
  const socketList = clients.get(userId) || [];
  for (const socket of socketList) {
    if (socket.readyState === 1) {
      socket.send(JSON.stringify(payload));
    }
  }
}

function broadcastPresence(userId, online) {
  const db = readDb();
  for (const conversation of db.conversations) {
    if ((conversation.participants || []).includes(userId)) {
      for (const participantId of conversation.participants || []) {
        if (participantId !== userId) {
          broadcastToUser(participantId, {
            type: 'presence:update',
            userId,
            online,
          });
        }
      }
    }
  }
}

wss.on('connection', (socket, req) => {
  const params = new URL(req.url, 'http://localhost');
  const token = params.searchParams.get('token');
  if (!token) {
    socket.close();
    return;
  }

  let decoded;
  try {
    decoded = jwt.verify(token, jwtSecret);
  } catch (error) {
    socket.close();
    return;
  }

  const user = getUserById(decoded.sub);
  if (!user) {
    socket.close();
    return;
  }

  if (!clients.has(user.id)) clients.set(user.id, new Set());
  clients.get(user.id).add(socket);

  socket.userId = user.id;
  socket.send(JSON.stringify({ type: 'welcome', user: sanitizeUser(user) }));
  broadcastPresence(user.id, true);

  socket.on('message', (raw) => {
    try {
      const data = JSON.parse(String(raw));

      if (data.type === 'typing:start' || data.type === 'typing:stop') {
        const conversation = getConversationById(data.conversationId);
        if (!conversation || !(conversation.participants || []).includes(user.id)) return;

        for (const participantId of conversation.participants || []) {
          if (participantId === user.id) continue;
          broadcastToUser(participantId, {
            type: data.type,
            userId: user.id,
            conversationId: data.conversationId,
          });
        }
      }

      if (data.type === 'call:invite' || data.type === 'call:accept' || data.type === 'call:reject' || data.type === 'webrtc:offer' || data.type === 'webrtc:answer' || data.type === 'webrtc:ice') {
        const targetUserId = data.targetUserId;
        if (!targetUserId) return;
        broadcastToUser(targetUserId, {
          ...data,
          fromUserId: user.id,
          fromName: user.displayName,
        });
      }
    } catch (error) {
      // ignore malformed messages
    }
  });

  socket.on('close', () => {
    const connectionSet = clients.get(user.id);
    if (connectionSet) {
      connectionSet.delete(socket);
      if (!connectionSet.size) {
        clients.delete(user.id);
        broadcastPresence(user.id, false);
      }
    }
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

server.listen(port, () => {
  console.log(`Nexus server listening on http://localhost:${port}`);
});
