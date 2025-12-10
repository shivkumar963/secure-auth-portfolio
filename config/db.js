const mongoose = require('mongoose');

// Dono naam support karenge: MONGO_URI ya MONGODB_URI
const MONGO_URI =
  process.env.MONGO_URI ||
  process.env.MONGODB_URI ||   // <- ye line add
  'mongodb://0.0.0.0/men';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("✅ Connected to Database");
  })
  .catch((err) => {
    console.error("❌ Error in Database", err);
  });

module.exports = mongoose;