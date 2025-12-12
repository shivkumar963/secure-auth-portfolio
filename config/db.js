require('dotenv').config();
const mongoose = require('mongoose');

mongoose.set('strictQuery', false);

const MONGO_URL = process.env.MONGO_URL;
if (!MONGO_URL) {
  console.error("❌ MONGO_URL missing in .env or Render env vars");
  process.exit(1);
}

mongoose.connect(MONGO_URL)
  .then(() => console.log("✅ Connected to Database"))
  .catch(err => {
    console.error("❌ MongoDB Connection Failed:", err);
    process.exit(1);
  });

module.exports = mongoose;