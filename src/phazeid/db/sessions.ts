import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  token: String,
  createdOn: Date,
  expiresOn: Date,

  userID: String,
  hasMfa: Boolean,

  valid: Boolean,
  challengeCode: String,

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
  },

  oauthApps: [ String ],
  oauthSession: String
})

export default mongoose.model('Session', schema);