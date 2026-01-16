// C:\code\backend\config\db.js
const mongoose = require('mongoose');
const connectDB = async () => {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await mongoose.connect(process.env.MONGODB_URL, {
        serverSelectionTimeoutMS: 5000,
        autoCreate: true, // Explicitly enable autoCreate
        autoIndex: true,   // Explicitly enable autoIndex
        family: 4,         // ✅ Force IPv4 to fix connection issues
      });
      console.log('MongoDB connected successfully');
      return;
    } catch (err) {
      console.error(`MongoDB connection attempt ${attempt} failed:`, err.message);
      if (attempt === 3) {
        console.error('All MongoDB connection attempts failed. Exiting...');
        process.exit(1);
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
};
module.exports = connectDB;
