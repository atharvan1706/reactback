import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    plantId: { type: String, required: true }
  },
  { timestamps: true }
);

export default mongoose.model('User', UserSchema);
