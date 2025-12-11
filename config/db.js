const mongoose = require('mongoose');

const mongoUrl = process.env.MONGO_URL || process.env.MONGO_URI || process.env.MONGODB_URL;

if (!mongoUrl) {
  console.error('❌ MONGO URL missing. Set MONGO_URL in .env');
  process.exit(1);
}

async function connectDB() {
  try {
    await mongoose.connect(mongoUrl); // options not needed in mongoose v6+
    console.log('✅ MongoDB Connected Successfully');
  } catch (err) {
    console.error('❌ MongoDB Connection Failed:', err.message || err);
    process.exit(1);
  }
}

module.exports = connectDB;