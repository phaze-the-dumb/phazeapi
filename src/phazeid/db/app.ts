import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  ownerID: String,
  token: String,
  redirectUri: String
})

export default mongoose.model('App', schema);