import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  username: String,
  password: String,

  lastUsernameChange: Date,
  lastPasswordChange: Date,

  passwordChangeToken: String,

  loginAttempts: Number,
  accountLocked: Boolean,
  lockedUntil: Number,

  email: String,
  emailVerificationCode: String,
  emailVerified: Boolean,
  lastEmailChange: Date,

  avatar: String,
  lastAvatarChange: Date,

  hasMfa: Boolean,
  mfaString: String,

  roles: [ String ],
  allowedApps: [ String ],

  sessions: [ String ],

  patreon: {
    id: String,
    currentTiers: [ { id: String, title: String } ],
    lastUpdate: Number,
    token: String,
    refreshToken: String
  }
})

export default mongoose.model('User', schema);