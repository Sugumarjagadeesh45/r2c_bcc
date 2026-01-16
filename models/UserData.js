const mongoose = require('mongoose');

const UserDataSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      unique: true
    },
    profilePicture: {
      type: String,
      default: ''
    },
    bio: {
      type: String,
      maxlength: 500,
      default: ''
    },
    location: {
      type: {
        type: String,
        enum: ['Point'],
        default: 'Point'
      },
      coordinates: {
        type: [Number],
        default: [0, 0]
      }
    },
    website: {
      type: String,
      default: ''
    },
    socialLinks: {
      instagram: { type: String, default: '' },
      twitter: { type: String, default: '' },
      facebook: { type: String, default: '' },
      youtube: { type: String, default: '' }
    },
    interests: [{
      type: String,
      trim: true
    }],
    preferences: {
      notifications: { type: Boolean, default: true },
      emailUpdates: { type: Boolean, default: true },
      privateAccount: { type: Boolean, default: false },
      showOnlineStatus: { type: Boolean, default: true }
    },
    stats: {
      postsCount: { type: Number, default: 0 },
      followersCount: { type: Number, default: 0 },
      followingCount: { type: Number, default: 0 },
      likesCount: { type: Number, default: 0 }
    },
    isOnline: {
      type: Boolean,
      default: false,
    },
    lastActive: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

// Index for faster queries
UserDataSchema.index({ userId: 1 });
UserDataSchema.index({ location: '2dsphere' });


// Virtual for profile completion percentage
UserDataSchema.virtual('profileCompletion').get(function() {
  const interestsLength = Array.isArray(this.interests) ? this.interests.length : 0;

  const fields = [
    this.profilePicture,
    this.bio,
    this.location,
    interestsLength
  ];

  const completedFields = fields.filter(field => {
    if (typeof field === 'number') return field > 0;
    if (Array.isArray(field)) return field.length > 0;
    return field && field.toString().trim().length > 0;
  }).length;

  return Math.round((completedFields / fields.length) * 100);
});


// Ensure virtual fields are serialized
UserDataSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('UserData', UserDataSchema);