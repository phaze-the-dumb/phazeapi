import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  token: String,
  appID: String,
  valid: Boolean,
  userID: String
})

export default mongoose.model('OauthSession', schema);