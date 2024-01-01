import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  username: String,
  password: String,

  avatar: String,

  hasMfa: Boolean,
  mfaString: String,

  roles: [ String ],
  allowedApps: [ String ],

  sessions: [{
    token: String,
    createdOn: Date,
    expiresOn: Date,
    loc: {
      ip: String,
      hostname: String,
      city: String,
      region: String,
      country: String,
      loc: String,
      org: String,
      postal: String,
      timezone: String
    }
  }]
})

export default mongoose.model('User', schema);