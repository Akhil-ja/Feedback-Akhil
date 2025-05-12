import { Schema, model } from 'mongoose';
import { IUser } from '../interface/common.interface';
import { USER_ROLES, USER_STATUSES } from '../constants/user.constants';

const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  first_name: {
    type: String,
    trim: true,
  },
  last_name: {
    type: String,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: USER_ROLES,
    required: true,
  },
  created_at: {
    type: Date,
    default: Date.now,
    immutable: true,
  },
  edited_at: {
    type: Date,
    default: Date.now,
  },
  resetPasswordOTP: {
    type: String,
  },
  resetPasswordOTPExpires: {
    type: Date,
    expires: 300,
  },

  status: {
    type: String,
    enum: USER_STATUSES,
    default: 'active',
  },
});

userSchema.pre('save', function (next) {
  if (!this.isNew) {
    this.edited_at = new Date();
  }
  next();
});

const User = model<IUser>('User', userSchema);

export default User;
