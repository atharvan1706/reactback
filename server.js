// backend/server.js
import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import User from './models/User.js';
import InvitationCode from './models/InvitationCode.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const REQUIRE_ADMIN_APPROVAL = process.env.REQUIRE_ADMIN_APPROVAL === 'true';

// ================= DATABASE =================
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ================= MIDDLEWARE =================
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://reactfront-production-101d.up.railway.app');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

// ================= AUTH MIDDLEWARE =================
function authenticateJWT(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

// Admin role check middleware
function requireAdmin(req, res, next) {
  User.findById(req.userId)
    .then(user => {
      if (!user || user.globalRole !== 'admin' && user.globalRole !== 'superadmin') {
        return res.status(403).json({ success: false, message: 'Admin access required' });
      }
      req.user = user;
      next();
    })
    .catch(err => {
      res.status(500).json({ success: false, message: 'Server error' });
    });
}

// Plant access check middleware
function requirePlantAccess(requiredRole = 'operator') {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.userId);
      const { plantId } = req.params || req.query || req.body;
      
      if (!plantId) {
        return res.status(400).json({ success: false, message: 'Plant ID required' });
      }

      if (!user.hasPlantAccess(plantId, requiredRole)) {
        return res.status(403).json({ 
          success: false, 
          message: 'Insufficient permissions for this plant' 
        });
      }

      req.user = user;
      req.plantRole = user.getPlantRole(plantId);
      next();
    } catch (err) {
      res.status(500).json({ success: false, message: 'Server error' });
    }
  };
}

// ================= HELPER FUNCTIONS =================
function generateInvitationCode(plantId) {
  const randomBytes = crypto.randomBytes(8).toString('hex').toUpperCase();
  const prefix = plantId.toUpperCase().substring(0, 6).padEnd(6, 'X');
  return `${prefix}-${randomBytes}`;
}

// ================= ADMIN: INVITATION MANAGEMENT =================

// Generate invitation code
app.post('/api/admin/invitations', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { plantId, role = 'operator', expiresInDays = 7, maxUses = 1 } = req.body;

    if (!plantId) {
      return res.status(400).json({ success: false, message: 'Plant ID required' });
    }

    const code = generateInvitationCode(plantId);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);

    const invitation = await InvitationCode.create({
      code,
      plantId,
      role,
      createdBy: req.userId,
      expiresAt,
      maxUses
    });

    res.json({
      success: true,
      code: invitation.code,
      plantId: invitation.plantId,
      role: invitation.role,
      expiresAt: invitation.expiresAt,
      maxUses: invitation.maxUses,
      shareUrl: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/register?code=${invitation.code}`
    });
  } catch (err) {
    console.error('❌ Generate invitation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// List invitations
app.get('/api/admin/invitations', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { plantId, status } = req.query;
    const filter = {};

    if (plantId) filter.plantId = plantId;
    if (status === 'active') {
      filter.isActive = true;
      filter.expiresAt = { $gt: new Date() };
    } else if (status === 'expired') {
      filter.expiresAt = { $lte: new Date() };
    } else if (status === 'used') {
      filter.usedBy = { $ne: null };
    }

    const invitations = await InvitationCode.find(filter)
      .populate('createdBy', 'name email')
      .populate('usedBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(100);

    res.json({
      success: true,
      invitations: invitations.map(inv => ({
        code: inv.code,
        plantId: inv.plantId,
        role: inv.role,
        createdBy: inv.createdBy?.name,
        createdAt: inv.createdAt,
        expiresAt: inv.expiresAt,
        isActive: inv.isActive,
        isValid: inv.isValid(),
        usedBy: inv.usedBy?.name,
        usedAt: inv.usedAt,
        maxUses: inv.maxUses,
        timesUsed: inv.timesUsed
      }))
    });
  } catch (err) {
    console.error('❌ List invitations error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Revoke invitation
app.delete('/api/admin/invitations/:code', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { code } = req.params;
    
    const invitation = await InvitationCode.findOne({ code });
    if (!invitation) {
      return res.status(404).json({ success: false, message: 'Invitation not found' });
    }

    invitation.isActive = false;
    await invitation.save();

    res.json({ success: true, message: 'Invitation revoked' });
  } catch (err) {
    console.error('❌ Revoke invitation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= ADMIN: USER MANAGEMENT =================

// List all users
app.get('/api/admin/users', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { plantId, status } = req.query;
    const filter = {};

    if (status) filter.status = status;
    if (plantId) filter['plantAccess.plantId'] = plantId;

    const users = await User.find(filter)
      .select('-password')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      users: users.map(user => ({
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status,
        globalRole: user.globalRole,
        plantAccess: user.plantAccess,
        invitationCode: user.invitationCode,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }))
    });
  } catch (err) {
    console.error('❌ List users error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Approve pending user
app.post('/api/admin/users/:userId/approve', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'User is not pending approval' });
    }

    user.status = 'active';
    await user.save();

    // TODO: Send email notification to user

    res.json({ 
      success: true, 
      message: 'User approved',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status
      }
    });
  } catch (err) {
    console.error('❌ Approve user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Suspend user
app.post('/api/admin/users/:userId/suspend', authenticateJWT, requireAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.status = 'suspended';
    await user.save();

    res.json({ success: true, message: 'User suspended' });
  } catch (err) {
    console.error('❌ Suspend user error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH: VERIFY INVITATION =================
app.get('/api/auth/verify-invitation', async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).json({ success: false, message: 'Code required' });
    }

    const invitation = await InvitationCode.findOne({ code: code.toUpperCase() });

    if (!invitation) {
      return res.json({ 
        success: true, 
        valid: false, 
        message: 'Invalid invitation code' 
      });
    }

    if (!invitation.isValid()) {
      return res.json({ 
        success: true, 
        valid: false, 
        message: invitation.expiresAt < new Date() ? 'Invitation code expired' : 'Invitation code already used' 
      });
    }

    res.json({
      success: true,
      valid: true,
      plantId: invitation.plantId,
      role: invitation.role,
      expiresAt: invitation.expiresAt
    });
  } catch (err) {
    console.error('❌ Verify invitation error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH: REGISTER =================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, invitationCode } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    if (!invitationCode) {
      return res.status(400).json({ success: false, message: 'Invitation code is required' });
    }

    // Check if user exists
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ success: false, message: 'User already exists' });
    }

    // Validate invitation code
    const invitation = await InvitationCode.findOne({ code: invitationCode.toUpperCase() });
    
    if (!invitation || !invitation.isValid()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired invitation code' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Determine initial status
    const status = REQUIRE_ADMIN_APPROVAL ? 'pending' : 'active';

    // Create user with plant access
    const user = await User.create({
      email,
      password: hashedPassword,
      name,
      plantId: invitation.plantId, // Legacy field
      plantAccess: [{
        plantId: invitation.plantId,
        role: invitation.role,
        grantedBy: invitation.createdBy,
        grantedAt: new Date()
      }],
      status,
      invitationCode: invitation.code
    });

    // Mark invitation as used
    invitation.timesUsed += 1;
    if (invitation.timesUsed >= invitation.maxUses) {
      invitation.usedBy = user._id;
      invitation.usedAt = new Date();
    }
    await invitation.save();

    // Generate token (even for pending users, they'll need it to check status)
    const token = jwt.sign(
      { id: user._id, plantId: invitation.plantId }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: status === 'pending' 
        ? 'Account created. Awaiting admin approval.' 
        : 'Account created successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status,
        plantAccess: user.plantAccess
      },
      token,
      requiresApproval: status === 'pending'
    });
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH: LOGIN =================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check if account is suspended
    if (user.status === 'suspended') {
      return res.status(403).json({ 
        success: false, 
        message: 'Account suspended. Contact administrator.' 
      });
    }

    // Check if account is pending
    if (user.status === 'pending') {
      return res.status(403).json({ 
        success: false, 
        message: 'Account pending admin approval',
        requiresApproval: true
      });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      { id: user._id, plantId: user.plantId }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        plantId: user.plantId,
        plantAccess: user.plantAccess,
        globalRole: user.globalRole
      },
      token
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ================= AUTH: VERIFY =================
app.get('/api/auth/verify', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false });
    }

    res.json({ 
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        status: user.status,
        plantAccess: user.plantAccess,
        globalRole: user.globalRole
      }
    });
  } catch (err) {
    res.status(401).json({ success: false });
  }
});

// ================= HTTP SERVER =================
const server = http.createServer(app);

// ================= WEBSOCKET SERVER =================
const wss = new WebSocketServer({ server });
const agents = new Map();

wss.on('connection', (ws) => {
  console.log('🔌 Agent connected');

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());

      if (data.type === 'REGISTER_AGENT') {
        ws.plantId = data.plantId;
        agents.set(data.plantId, ws);
        console.log(`✅ Agent registered: ${data.plantId}`);
      }

      if (data.type === 'QUERY_RESPONSE') ws.lastResponse = data.payload;
      if (data.type === 'LIVE_DATA') ws.lastLive = data.payload;
    } catch (err) {
      console.error('❌ WS error:', err.message);
    }
  });

  ws.on('close', () => {
    if (ws.plantId) {
      agents.delete(ws.plantId);
      console.log(`❌ Agent disconnected: ${ws.plantId}`);
    }
  });
});

// ================= QUESTDB QUERY (Protected) =================
app.get('/api/questdb/query', authenticateJWT, requirePlantAccess('operator'), async (req, res) => {
  const { sql, plantId } = req.query;

  if (!sql || !plantId) {
    return res.status(400).json({ error: 'sql and plantId required' });
  }

  const agent = agents.get(plantId);
  if (!agent) {
    return res.status(503).json({ 
      error: `Agent for ${plantId} is offline`, 
      columns: [], 
      dataset: [] 
    });
  }

  agent.send(JSON.stringify({ type: 'EXEC_QUERY', sql }));
  await new Promise(resolve => setTimeout(resolve, 500));

  res.json(agent.lastResponse || { columns: [], dataset: [] });
});

// ================= HEALTH =================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    agents: [...agents.keys()], 
    time: new Date().toISOString() 
  });
});

// ================= START =================
server.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
  console.log(`🔌 WebSocket active on same port`);
  console.log(`🔐 Admin approval required: ${REQUIRE_ADMIN_APPROVAL}`);
});
