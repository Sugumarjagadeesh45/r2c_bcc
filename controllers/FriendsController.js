const User = require('../models/userModel');
const Friendship = require('../models/Friendship');
const FriendRequest = require('../models/FriendRequest');
const UserData = require('../models/UserData');
const mongoose = require('mongoose');
const fcmService = require('../services/fcmService');

// Helper function to safely convert IDs to string
const toStringId = (id) => (id ? id.toString() : id);

exports.getFriends = async (req, res) => {
  try {
    const userId = req.user.id;

    // Find all accepted friendships where user is involved
    const friendships = await Friendship.find({
      $or: [
        { user1: userId, status: 'accepted' },
        { user2: userId, status: 'accepted' }
      ]
    })
      .populate('user1', 'name email userId photoURL phone')
      .populate('user2', 'name email userId photoURL phone')
      .sort({ lastInteraction: -1 });

    // Extract friend details
    const friendsData = await Promise.all(friendships.map(async (friendship) => {
      // Check if populated users exist (handle deleted users)
      if (!friendship.user1 || !friendship.user2) {
        return null;
      }

      const friend = toStringId(friendship.user1._id) === toStringId(userId)
        ? friendship.user2
        : friendship.user1;

      const userData = await UserData.findOne({ userId: friend._id });

      return {
        id: friend._id,
        userId: friend.userId,
        name: friend.name,
        email: friend.email,
        photoURL: friend.photoURL || null,
        phone: friend.phone || '',
        friendshipId: friendship._id,
        lastInteraction: friendship.lastInteraction || friendship.updatedAt || friendship.acceptedAt || null,
        status: 'friend',
        isOnline: userData ? userData.isOnline : false,
        lastSeen: userData ? userData.lastActive : null,
      };
    }));

    const friends = friendsData.filter(f => f !== null);

    return res.json({
      success: true,
      friends,
      count: friends.length
    });
  } catch (error) {
    console.error('Get friends error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get friend suggestions based on birth year (±5 years by default)
exports.getFriendSuggestions = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select('dateOfBirth');

    if (!user || !user.dateOfBirth) {
      return res.status(400).json({
        success: false,
        message: 'User date of birth not found',
        suggestions: []
      });
    }

    const birthYear = new Date(user.dateOfBirth).getFullYear();
    const minYear = birthYear - 5;
    const maxYear = birthYear + 5;

    // Get existing accepted friendships (to exclude)
    const existingFriendships = await Friendship.find({
      $or: [{ user1: userId }, { user2: userId }],
      status: { $in: ['accepted', 'blocked'] } // exclude blocked/accepted
    });

    const excludedUserIds = new Set([toStringId(userId)]);
    existingFriendships.forEach(f => {
      const other = toStringId(f.user1) === toStringId(userId) ? f.user2 : f.user1;
      excludedUserIds.add(toStringId(other));
    });

    // Find candidate users with DOB within range, excluding already friends/blocked/self
    const suggestions = await User.find({
      dateOfBirth: {
        $gte: new Date(`${minYear}-01-01`),
        $lt: new Date(`${maxYear + 1}-01-01`)
      },
      _id: { $nin: Array.from(excludedUserIds) }
    })
      .select('name email userId photoURL dateOfBirth')
      .limit(20);

    // Build a set of current user's friend ids for mutual calculation
    const userFriendIds = existingFriendships
      .filter(f => f.status === 'accepted')
      .map(f => (toStringId(f.user1) === toStringId(userId) ? f.user2.toString() : f.user1.toString()));

    // For each suggestion, determine friend-request status and mutual friends count
    const suggestedUsers = await Promise.all(suggestions.map(async (s) => {
      // Check for existing friend request either direction
      const existingRequest = await FriendRequest.findOne({
        $or: [
          { fromUserId: userId, toUserId: s._id },
          { fromUserId: s._id, toUserId: userId }
        ]
      });

      let requestStatus = 'add_friend';
      if (existingRequest) {
        if (existingRequest.status === 'pending') {
          requestStatus = existingRequest.fromUserId.toString() === toStringId(userId) ? 'request_sent' : 'request_received';
        } else if (existingRequest.status === 'accepted') {
          requestStatus = 'already_friends';
        } else if (existingRequest.status === 'rejected') {
          requestStatus = 'request_rejected';
        }
      }

      // Calculate mutual friends count (real calculation)
      const suggestionFriendships = await Friendship.find({
        $or: [{ user1: s._id }, { user2: s._id }],
        status: 'accepted'
      });

      const suggestionFriendIds = new Set(
        suggestionFriendships.map(f => (toStringId(f.user1) === toStringId(s._id) ? f.user2.toString() : f.user1.toString()))
      );

      const mutualCount = userFriendIds.reduce((acc, id) => suggestionFriendIds.has(id) ? acc + 1 : acc, 0);

      return {
        id: s._id,
        userId: s.userId,
        name: s.name,
        email: s.email,
        avatar: s.photoURL || null,
        dateOfBirth: s.dateOfBirth,
        status: `${mutualCount} mutual friends`,
        requestStatus
      };
    }));

    return res.json({
      success: true,
      suggestions: suggestedUsers
    });
  } catch (error) {
    console.error('Get friend suggestions error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error',
      suggestions: []
    });
  }
};

// Send friend request
exports.sendFriendRequest = async (req, res) => {
  try {
    const { toUserId, recipientId, message } = req.body;
    const fromUserId = req.user.id;
    
    const recipientIdentifier = toUserId || recipientId;

    if (!recipientIdentifier) {
      return res.status(400).json({ success: false, message: 'toUserId or recipientId is required' });
    }

    if (toStringId(recipientIdentifier) === toStringId(fromUserId)) {
      return res.status(400).json({ success: false, message: 'Cannot send friend request to yourself' });
    }

    // Validate recipient exists
    let toUser;
    if (mongoose.Types.ObjectId.isValid(recipientIdentifier)) {
      toUser = await User.findById(recipientIdentifier);
    } else {
      toUser = await User.findOne({ userId: recipientIdentifier });
    }
    
    if (!toUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const toUserIdFound = toUser._id;

    // Check if already friends or blocked
    const existingFriendship = await Friendship.findOne({
      $or: [
        { user1: fromUserId, user2: toUserIdFound },
        { user1: toUserIdFound, user2: fromUserId }
      ]
    });

    if (existingFriendship) {
      if (existingFriendship.status === 'accepted') {
        return res.status(400).json({ success: false, message: 'Already friends with this user' });
      }
      if (existingFriendship.status === 'blocked') {
        return res.status(400).json({ success: false, message: 'Cannot send request — user is blocked or has blocked you' });
      }
    }

    // Check for existing friend request
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { fromUserId, toUserId: toUserIdFound },
        { fromUserId: toUserIdFound, toUserId: fromUserId }
      ]
    });

    if (existingRequest) {
      if (existingRequest.status === 'pending') {
        if (existingRequest.fromUserId.toString() === fromUserId.toString()) {
          return res.status(400).json({ success: false, message: 'Friend request already sent' });
        } else {
          // Other user sent the request — maybe accept flow instead of sending new one
          return res.status(400).json({ success: false, message: 'This user has already sent you a friend request' });
        }
      } else if (existingRequest.status === 'accepted') {
        return res.status(400).json({ success: false, message: 'Already friends with this user' });
      } else if (existingRequest.status === 'rejected') {
        // allow sending a fresh request: remove old rejected request
        await FriendRequest.deleteOne({ _id: existingRequest._id });
      }
    }

    // Create new friend request
    const friendRequest = new FriendRequest({
      fromUserId,
      toUserId: toUserIdFound,
      message: message || '',
      status: 'pending',
      seen: false
    });

    await friendRequest.save();

    // Send FCM notification to the recipient (fire and forget)
    fcmService.sendFriendRequestNotification(toUserIdFound, req.user);

    // Optionally populate for response
    const populatedRequest = await FriendRequest.findById(friendRequest._id)
      .populate('fromUserId', 'name email userId photoURL phone')
      .populate('toUserId', 'name email userId photoURL phone');

    return res.json({
      success: true,
      message: 'Friend request sent successfully',
      friendRequest: populatedRequest
    });
  } catch (error) {
    console.error('Send friend request error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Accept friend request
exports.acceptFriendRequest = async (req, res) => {
  try {
    const { requestId } = req.params;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(requestId)) {
      return res.status(400).json({ success: false, message: 'Invalid request id' });
    }

    // Find the friend request intended for this user
    const friendRequest = await FriendRequest.findOne({
      _id: requestId,
      toUserId: userId,
      status: 'pending'
    });

    if (!friendRequest) {
      return res.status(404).json({ success: false, message: 'Friend request not found or already processed' });
    }

    // Update request
    friendRequest.status = 'accepted';
    friendRequest.seen = true;
    await friendRequest.save();

    // Avoid duplicate friendships
    const alreadyFriendship = await Friendship.findOne({
      $or: [
        { user1: friendRequest.fromUserId, user2: friendRequest.toUserId },
        { user1: friendRequest.toUserId, user2: friendRequest.fromUserId }
      ],
      status: 'accepted'
    });

    if (alreadyFriendship) {
      return res.json({ success: true, message: 'Friend request accepted', friendship: alreadyFriendship });
    }

    // Create friendship record
    const friendship = new Friendship({
      user1: friendRequest.fromUserId,
      user2: friendRequest.toUserId,
      status: 'accepted',
      requestedBy: friendRequest.fromUserId,
      acceptedAt: new Date(),
      lastInteraction: new Date()
    });

    await friendship.save();

    // Notify the original sender that their request was accepted (fire and forget)
    fcmService.sendFriendRequestAcceptedNotification(friendRequest.fromUserId, req.user);

    return res.json({
      success: true,
      message: 'Friend request accepted successfully',
      friendship
    });
  } catch (error) {
    console.error('Accept friend request error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Reject friend request
exports.rejectFriendRequest = async (req, res) => {
  try {
    const { requestId } = req.params;
    const userId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(requestId)) {
      return res.status(400).json({ success: false, message: 'Invalid request id' });
    }

    const friendRequest = await FriendRequest.findOne({
      _id: requestId,
      toUserId: userId,
      status: 'pending'
    });

    if (!friendRequest) {
      return res.status(404).json({ success: false, message: 'Friend request not found or already processed' });
    }

    friendRequest.status = 'rejected';
    friendRequest.seen = true;
    await friendRequest.save();

    return res.json({
      success: true,
      message: 'Friend request rejected successfully'
    });
  } catch (error) {
    console.error('Reject friend request error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get pending friend requests for current user (incoming)
exports.getPendingRequests = async (req, res) => {
  try {
    const userId = req.user.id;

    const pendingRequests = await FriendRequest.find({
      toUserId: userId,
      status: 'pending'
    })
      .populate('fromUserId', 'name email userId photoURL phone dateOfBirth gender')
      .sort({ createdAt: -1 });

    const requestsWithData = await Promise.all(pendingRequests.map(async (request) => {
      const userData = await UserData.findOne({ userId: request.fromUserId._id });

      return {
        id: request._id,
        fromUser: {
          id: request.fromUserId._id,
          userId: request.fromUserId.userId,
          name: request.fromUserId.name,
          email: request.fromUserId.email,
          avatar: request.fromUserId.photoURL || null,
          phone: request.fromUserId.phone || '',
          dateOfBirth: request.fromUserId.dateOfBirth,
          gender: request.fromUserId.gender || '',
          bio: userData?.bio || '',
          location: userData?.location || '',
          interests: userData?.interests || []
        },
        message: request.message,
        createdAt: request.createdAt,
        seen: request.seen
      };
    }));

    return res.json({
      success: true,
      requests: requestsWithData,
      count: requestsWithData.length
    });
  } catch (error) {
    console.error('Get pending requests error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get sent friend requests by current user (pending)
exports.getSentRequests = async (req, res) => {
  try {
    const userId = req.user.id;

    const sentRequests = await FriendRequest.find({
      fromUserId: userId,
      status: 'pending'
    })
      .populate('toUserId', 'name email userId photoURL phone')
      .sort({ createdAt: -1 });

    return res.json({
      success: true,
      requests: sentRequests,
      count: sentRequests.length
    });
  } catch (error) {
    console.error('Get sent requests error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Remove friend (unfriend) - marks friendship deleted and rejects related requests
exports.removeFriend = async (req, res) => {
  try {
    const { friendId } = req.params;
    const userId = req.user.id;

    if (!friendId) {
      return res.status(400).json({ success: false, message: 'friendId is required' });
    }

    const friendship = await Friendship.findOne({
      $or: [
        { user1: userId, user2: friendId, status: 'accepted' },
        { user1: friendId, user2: userId, status: 'accepted' }
      ]
    });

    if (!friendship) {
      return res.status(404).json({ success: false, message: 'Friendship not found' });
    }

    friendship.status = 'deleted';
    friendship.deletedAt = new Date();
    await friendship.save();

    // Update any friend requests between the users to rejected
    await FriendRequest.updateMany(
      {
        $or: [
          { fromUserId: userId, toUserId: friendId },
          { fromUserId: friendId, toUserId: userId }
        ]
      },
      { status: 'rejected' }
    );

    return res.json({
      success: true,
      message: 'Friend removed successfully'
    });
  } catch (error) {
    console.error('Remove friend error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Block user
exports.blockUser = async (req, res) => {
  try {
    const { userId: otherUserId } = req.params;
    const currentUserId = req.user.id;

    if (!otherUserId) {
      return res.status(400).json({ success: false, message: 'userId parameter is required' });
    }

    // Find existing friendship (any status)
    let friendship = await Friendship.findOne({
      $or: [
        { user1: currentUserId, user2: otherUserId },
        { user1: otherUserId, user2: currentUserId }
      ]
    });

    if (friendship) {
      friendship.status = 'blocked';
      friendship.blockedAt = new Date();
      friendship.blockedBy = currentUserId;
    } else {
      friendship = new Friendship({
        user1: currentUserId,
        user2: otherUserId,
        status: 'blocked',
        requestedBy: currentUserId,
        blockedAt: new Date(),
        blockedBy: currentUserId
      });
    }

    await friendship.save();

    // Reject any pending friend requests between the users
    await FriendRequest.updateMany(
      {
        $or: [
          { fromUserId: currentUserId, toUserId: otherUserId },
          { fromUserId: otherUserId, toUserId: currentUserId }
        ],
        status: 'pending'
      },
      { status: 'rejected' }
    );

    return res.json({
      success: true,
      message: 'User blocked successfully'
    });
  } catch (error) {
    console.error('Block user error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Search users for friend adding (name/email/userId/phone)
exports.searchUsersForFriends = async (req, res) => {
  try {
    const { query } = req.query;
    const userId = req.user.id;

    if (!query || query.length < 2) {
      return res.status(400).json({
        success: false,
        message: 'Search query must be at least 2 characters'
      });
    }

    // Basic search
    const users = await User.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { email: { $regex: query, $options: 'i' } },
        { userId: { $regex: query, $options: 'i' } },
        { phone: { $regex: query, $options: 'i' } }
      ],
      _id: { $ne: userId }
    })
      .select('name email userId photoURL phone dateOfBirth')
      .limit(20);

    const usersWithStatus = await Promise.all(users.map(async (u) => {
      // Check friendship accepted
      const existingFriendship = await Friendship.findOne({
        $or: [
          { user1: userId, user2: u._id, status: 'accepted' },
          { user1: u._id, user2: userId, status: 'accepted' }
        ]
      });

      // Check if blocked
      const blocked = await Friendship.findOne({
        $or: [
          { user1: userId, user2: u._id, status: 'blocked' },
          { user1: u._id, user2: userId, status: 'blocked' }
        ]
      });

      // Check for requests between users
      const existingRequest = await FriendRequest.findOne({
        $or: [
          { fromUserId: userId, toUserId: u._id },
          { fromUserId: u._id, toUserId: userId }
        ]
      });

      let friendshipStatus = 'add_friend';
      let requestId = null;

      if (blocked) {
        friendshipStatus = 'blocked';
      } else if (existingFriendship) {
        friendshipStatus = 'already_friends';
      } else if (existingRequest) {
        if (existingRequest.status === 'pending') {
          friendshipStatus = existingRequest.fromUserId.toString() === toStringId(userId) ? 'request_sent' : 'request_received';
          if (friendshipStatus === 'request_received') requestId = existingRequest._id;
        } else if (existingRequest.status === 'rejected') {
          friendshipStatus = 'request_rejected';
        } else if (existingRequest.status === 'accepted') {
          friendshipStatus = 'already_friends';
        }
      }

      const userData = await UserData.findOne({ userId: u._id });

      return {
        id: u._id,
        userId: u.userId,
        name: u.name,
        email: u.email,
        avatar: u.photoURL || null,
        phone: u.phone || '',
        dateOfBirth: u.dateOfBirth,
        bio: userData?.bio || '',
        location: userData?.location || '',
        interests: userData?.interests || [],
        friendshipStatus,
        requestId
      };
    }));

    return res.json({
      success: true,
      users: usersWithStatus,
      count: usersWithStatus.length
    });
  } catch (error) {
    console.error('Search users for friends error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// module.exports = {
//   getFriends,
//   getFriendSuggestions,
//   sendFriendRequest,
//   acceptFriendRequest,
//   rejectFriendRequest,
//   getPendingRequests,
//   getSentRequests,
//   removeFriend,
//   blockUser,
//   searchUsersForFriends
// };






// const User = require('../models/userModel');
// const FriendRequest = require('../models/FriendRequest');
// const UserData = require('../models/UserData');

// // Get friend suggestions based on birth year
// exports.getFriendSuggestions = async (req, res) => {
//   try {
//     const userId = req.user.id;
//     const user = await User.findById(userId);
    
//     if (!user || !user.dateOfBirth) {
//       return res.status(400).json({ success: false, message: 'User date of birth not found' });
//     }
    
//     const birthYear = new Date(user.dateOfBirth).getFullYear();
    
//     // Find users with the same birth year who are not already friends
//     const suggestions = await User.find({
//       dateOfBirth: {
//         $gte: new Date(`${birthYear}-01-01`),
//         $lt: new Date(`${birthYear + 1}-01-01`),
//       },
//       _id: { $ne: userId },
//     }).select('name email userId photoURL dateOfBirth').limit(10);
    
//     res.json({
//       success: true,
//       suggestions: suggestions.map(user => ({
//         ...user._doc,
//         status: `${Math.floor(Math.random() * 20) + 1} mutual friends`,
//       })),
//     });
//   } catch (error) {
//     console.error('Get friend suggestions error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };

// // Send friend request
// exports.sendFriendRequest = async (req, res) => {
//   try {
//     const { toUserId, message } = req.body;
//     const fromUserId = req.user.id;
    
//     // Check if request already exists
//     const existingRequest = await FriendRequest.findOne({
//       fromUserId,
//       toUserId,
//       status: 'pending',
//     });
    
//     if (existingRequest) {
//       return res.status(400).json({ success: false, message: 'Friend request already sent' });
//     }
    
//     // Create new friend request
//     const friendRequest = new FriendRequest({
//       fromUserId,
//       toUserId,
//       message: message || '',
//     });
    
//     await friendRequest.save();
    
//     res.json({
//       success: true,
//       message: 'Friend request sent successfully',
//     });
//   } catch (error) {
//     console.error('Send friend request error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };

// // Get friends list
// exports.getFriends = async (req, res) => {
//   try {
//     const userId = req.user.id;
    
//     // Find accepted friend requests where user is either sender or receiver
//     const friendRequests = await FriendRequest.find({
//       $or: [
//         { fromUserId: userId, status: 'accepted' },
//         { toUserId: userId, status: 'accepted' },
//       ],
//     });
    
//     // Extract friend IDs
//     const friendIds = friendRequests.map(request => {
//       return request.fromUserId.toString() === userId.toString() 
//         ? request.toUserId 
//         : request.fromUserId;
//     });
    
//     // Get friend details
//     const friends = await User.find({
//       _id: { $in: friendIds },
//     }).select('name email userId photoURL');
    
//     // Add random status for demo purposes
//     const friendsWithStatus = friends.map(friend => ({
//       ...friend._doc,
//       status: ['Active now', 'Active 5m ago', 'Active 1h ago', 'Active 3h ago', 'Active yesterday'][
//         Math.floor(Math.random() * 5)
//       ],
//     }));
    
//     res.json({
//       success: true,
//       friends: friendsWithStatus,
//     });
//   } catch (error) {
//     console.error('Get friends error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };