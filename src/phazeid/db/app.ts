import mongoose from "mongoose";

let schema = new mongoose.Schema({
  _id: String,

  ownerID: String,
  token: String,
})

export default mongoose.model('App', schema);