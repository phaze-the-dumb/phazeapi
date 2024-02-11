import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,
  name: String,
  ownerID: String,
  token: String,
  redirectUri: String
})

export default mongoose.model('App', schema);