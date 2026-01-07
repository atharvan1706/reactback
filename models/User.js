// backend/models/User.js
import mongoose from 'mongoose';

const plantAccessSchema = new mongoose.Schema({
  plantId: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['operator', 'manager', 'admin'],
    default: 'operator'
  },
  grantedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  grantedAt: {
    type: Date,
    default: Date.now
  }
});

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true
  },
  // Legacy field for backward compatibility
  plantId: {
    type: String
  },
  // New: Multiple plant access with roles
  plantAccess: [plantAccessSchema],
  // Account status
  status: {
    type: String,
    enum: ['active', 'pending', 'suspended'],
    default: 'active'
  },
  // Track which invitation code was used
  invitationCode: {
    type: String
  },
  // Global role (for super admins)
  globalRole: {
    type: String,
    enum: ['user', 'admin', 'superadmin'],
    default: 'user'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  }
});

// Helper method to check if user has access to a plant
userSchema.methods.hasPlantAccess = function(plantId, requiredRole = 'operator') {
  const roleHierarchy = { admin: 3, manager: 2, operator: 1 };
  
  // Super admins have access to everything
  if (this.globalRole === 'superadmin') return true;
  
  const access = this.plantAccess.find(pa => pa.plantId === plantId);
  if (!access) return false;
  
  return roleHierarchy[access.role] >= roleHierarchy[requiredRole];
};

// Helper method to get user's role for a specific plant
userSchema.methods.getPlantRole = function(plantId) {
  if (this.globalRole === 'superadmin') return 'admin';
  
  const access = this.plantAccess.find(pa => pa.plantId === plantId);
  return access ? access.role : null;
};

export default mongoose.model('User', userSchema);
