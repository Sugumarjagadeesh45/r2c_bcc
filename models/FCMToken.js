const mongoose = require("mongoose");

const fcmTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    unique: true,
  },
  token: {
    type: String,
    required: true,
    unique: true,
  },
  lastUpdated: {
    type: Date,
    default: Date.now,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Update `lastUpdated` before saving
fcmTokenSchema.pre('save', function(next) {
  this.lastUpdated = new Date();
  next();
});

const FCMToken = mongoose.model("FCMToken", fcmTokenSchema);

module.exports = FCMToken;
