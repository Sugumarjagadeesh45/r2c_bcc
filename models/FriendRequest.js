const mongoose = require('mongoose');

const FriendRequestSchema = new mongoose.Schema(
  {
    fromUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    toUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'rejected'],
      default: 'pending'
    },
    message: {
      type: String,
      default: ''
    },
    seen: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

// Index for faster queries
FriendRequestSchema.index({ fromUserId: 1, toUserId: 1 }, { unique: true });
FriendRequestSchema.index({ toUserId: 1, status: 1 });
FriendRequestSchema.index({ fromUserId: 1, status: 1 });

module.exports = mongoose.model('FriendRequest', FriendRequestSchema);





// const mongoose = require('mongoose');

// const FriendRequestSchema = new mongoose.Schema(
//   {
//     fromUserId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'User',
//       required: true,
//     },
//     toUserId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'User',
//       required: true,
//     },
//     status: {
//       type: String,
//       enum: ['pending', 'accepted', 'rejected'],
//       default: 'pending',
//     },
//     message: {
//       type: String,
//       default: '',
//     },
//   },
//   {
//     timestamps: true,
//   }
// );

// module.exports = mongoose.model('FriendRequest', FriendRequestSchema);