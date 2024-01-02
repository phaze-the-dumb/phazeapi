import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  username: String,
  password: String,

  email: String,
  emailVerificationCode: String,
  emailVerified: Boolean,

  avatar: String,

  hasMfa: Boolean,
  mfaString: String,

  roles: [ String ],
  allowedApps: [ String ],

  sessions: [ String ]
})

export default mongoose.model('User', schema);