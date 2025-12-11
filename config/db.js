const mongoose = require('mongoose');

// Dono naam support karenge: MONGO_URI ya MONGODB_URI
const MONGO_URL =
  process.env.MONGO_URL ||
  process.env.MONGODB_URL ||   // <- ye line add
  'mongodb://0.0.0.0/men';

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("🔥 MongoDB Atlas Connected Successfully"))
  .catch(err => console.error("❌ MongoDB Connection Failed:", err));

module.exports = mongoose;