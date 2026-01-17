const mongoose = require('mongoose');

const userLocationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true // One location entry per user
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true
    }
  },
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// 1. Geospatial Index for fast radius queries
userLocationSchema.index({ location: '2dsphere' });

// 2. TTL Index: Automatically delete documents 24 hours after 'updatedAt'
userLocationSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 86400 });

module.exports = mongoose.model('UserLocation', userLocationSchema);