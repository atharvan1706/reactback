// backend/models/InvitationCode.js
import mongoose from 'mongoose';

const invitationCodeSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    unique: true,
    uppercase: true
  },
  plantId: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['operator', 'manager', 'admin'],
    default: 'operator'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    required: true
  },
  usedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  usedAt: {
    type: Date,
    default: null
  },
  isActive: {
    type: Boolean,
    default: true
  },
  maxUses: {
    type: Number,
    default: 1
  },
  timesUsed: {
    type: Number,
    default: 0
  }
});

// Index for efficient lookups
invitationCodeSchema.index({ code: 1 });
invitationCodeSchema.index({ plantId: 1, isActive: 1 });
invitationCodeSchema.index({ expiresAt: 1 });

// Method to check if code is valid
invitationCodeSchema.methods.isValid = function() {
  if (!this.isActive) return false;
  if (this.expiresAt < new Date()) return false;
  if (this.timesUsed >= this.maxUses) return false;
  return true;
};

export default mongoose.model('InvitationCode', invitationCodeSchema);
