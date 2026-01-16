const mongoose = require('mongoose');

const FriendshipSchema = new mongoose.Schema(
  {
    user1: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    user2: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'rejected', 'blocked', 'deleted'],
      default: 'pending'
    },
    requestedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    // Metadata
    lastInteraction: {
      type: Date,
      default: Date.now
    },
    // For tracking friend requests
    requestMessage: {
      type: String,
      default: ''
    },
    // Timestamps for status changes
    acceptedAt: Date,
    rejectedAt: Date,
    blockedAt: Date,
    deletedAt: Date
  },
  {
    timestamps: true
  }
);

// Compound index to ensure unique friendships
FriendshipSchema.index({ user1: 1, user2: 1 }, { unique: true });

// Virtual for easier querying
FriendshipSchema.virtual('isActive').get(function() {
  return this.status === 'accepted';
});

// Virtual for easier querying
FriendshipSchema.virtual('isPending').get(function() {
  return this.status === 'pending';
});

// Set virtuals to JSON
FriendshipSchema.set('toJSON', { virtuals: true });

// Pre-save middleware to ensure user1 < user2 for consistency
FriendshipSchema.pre('save', function(next) {
  // Ensure user1 is always the smaller ObjectId for consistency
  if (this.user1.toString() > this.user2.toString()) {
    const temp = this.user1;
    this.user1 = this.user2;
    this.user2 = temp;
  }
  next();
});

module.exports = mongoose.model('Friendship', FriendshipSchema);