// config/db.js
require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URL = process.env.MONGO_URL;
if (!MONGO_URL) {
  console.error("❌ MONGO_URL missing in .env");
  process.exit(1);
}

mongoose.connect(MONGO_URL, {
  // NOTE: new mongoose versions don't need these; but harmless to include
  useNewUrlParser: true,
  useUnifiedTopology: true,
  // serverSelectionTimeoutMS: 5000 // optional: fail fast
}).then(() => {
  console.log("✅ Connected to Database");
}).catch(err => {
  console.error("❌ MongoDB Connection Failed:", err);
});

module.exports = mongoose;