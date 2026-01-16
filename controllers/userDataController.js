// D:\reals2chat_backend-main\controllers\userDataController.js
const mongoose = require('mongoose');
const UserData = require('../models/UserData');
const User = require('../models/userModel');
const Friendship = require('../models/Friendship');
const FriendRequest = require('../models/FriendRequest');

// Get user profile
const getUserProfile = async (req, res) => {
  try {
    console.log('Get user profile request for userId:', req.user.id);

    const user = await User.findById(req.user.id).select('-password');
    console.log('Full user data from database:', {
      _id: user._id,
      userId: user.userId,
      name: user.name,
      email: user.email
    });

    let userData = await UserData.findOne({ userId: req.user.id });
    
    console.log('Found userData:', userData);

    if (!userData) {
      console.log('No userData found, creating new one...');
      userData = new UserData({
        userId: req.user.id
      });
      await userData.save();
    }

    const responseData = {
      success: true,
      user: {
        id: user._id,
        userId: user.userId,
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        photoURL: user.photoURL,
        isPhoneVerified: user.isPhoneVerified,
        isEmailVerified: user.isEmailVerified,
        registrationComplete: user.registrationComplete
      },
      userData: userData
    };

    console.log('Returning profile data with userId:', responseData.user.userId);
    res.json(responseData);
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};


// D:\reals2chat_backend-main\controllers\userDataController.js

// Search users
const searchUsers = async (req, res) => {
  try {
    console.log('Search request received:', req.query);
    // Fix: Extract 'q' parameter and assign it to 'query' variable
    const { q: query, filter } = req.query;
    
    if (!query || query.length < 1) {
      console.log('Search query is empty or too short');
      return res.status(400).json({ success: false, message: 'Search query is required' });
    }

    // Build search criteria based on filter
    let searchCriteria = {};
    
    if (filter === 'name') {
      searchCriteria = { name: { $regex: query, $options: 'i' } };
    } else if (filter === 'email') {
      searchCriteria = { email: { $regex: query, $options: 'i' } };
    } else if (filter === 'phone') {
      searchCriteria = { phone: { $regex: query, $options: 'i' } };
    } else if (filter === 'userId') {
      searchCriteria = { userId: { $regex: query, $options: 'i' } };
    } else {
      // Search across all fields
      searchCriteria = {
        $or: [
          { name: { $regex: query, $options: 'i' } },
          { email: { $regex: query, $options: 'i' } },
          { phone: { $regex: query, $options: 'i' } },
          { userId: { $regex: query, $options: 'i' } },
        ],
      };
    }
    
    // Exclude current user
    searchCriteria._id = { $ne: req.user.id };
    
    console.log('Search criteria:', JSON.stringify(searchCriteria));
    
    const users = await User.find(searchCriteria)
      .select('name email userId photoURL phone')
      .limit(20);
    
    console.log(`Found ${users.length} users`);

    res.json({
      success: true,
      users: users,
    });
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Update user profile
const updateUserProfile = async (req, res) => {
  try {
    const {
      name,
      dateOfBirth,
      gender,
      bio,
      location,
      website,
      socialLinks,
      interests,
      preferences
    } = req.body;

    const userUpdate = {};
    if (name) userUpdate.name = name;
    if (dateOfBirth) userUpdate.dateOfBirth = dateOfBirth;
    if (gender) userUpdate.gender = gender;

    if (Object.keys(userUpdate).length > 0) {
      await User.findByIdAndUpdate(req.user.id, userUpdate);
    }

    const userDataUpdate = {};
    if (bio !== undefined) userDataUpdate.bio = bio;
    if (location !== undefined) userDataUpdate.location = location;
    if (website !== undefined) userDataUpdate.website = website;
    if (socialLinks) userDataUpdate.socialLinks = socialLinks;
    if (interests) userDataUpdate.interests = interests;
    if (preferences) userDataUpdate.preferences = preferences;

    const userData = await UserData.findOneAndUpdate(
      { userId: req.user.id },
      { $set: userDataUpdate },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    ).populate('userId', 'name email phone dateOfBirth gender photoURL registrationComplete userId');

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: userData.userId,
      userData: userData
    });
  } catch (error) {
    console.error('Update user profile error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Upload profile picture
const uploadProfilePicture = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Profile picture file is required' });
    }

    const profilePicturePath = `/uploads/profile/${req.file.filename}`;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id, 
      { photoURL: profilePicturePath },
      { new: true, select: 'name email phone dateOfBirth gender photoURL registrationComplete userId' }
    );

    const userData = await UserData.findOneAndUpdate(
      { userId: req.user.id },
      { $set: { profilePicture: profilePicturePath } },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    ).populate('userId', 'name email phone dateOfBirth gender photoURL registrationComplete userId');

    res.json({
      success: true,
      message: 'Profile picture updated successfully',
      user: updatedUser,
      userData: userData,
      profilePicture: profilePicturePath
    });
  } catch (error) {
    console.error('Upload profile picture error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get user stats
const getUserStats = async (req, res) => {
  try {
    const userData = await UserData.findOne({ userId: req.user.id })
      .populate('userId', 'name email userId phone dateOfBirth gender photoURL isPhoneVerified isEmailVerified registrationComplete');
    
    if (!userData) {
      return res.json({
        success: true,
        stats: {
          postsCount: 0,
          followersCount: 0,
          followingCount: 0,
          likesCount: 0
        },
        profileCompletion: 0
      });
    }

    res.json({
      success: true,
      stats: userData.stats,
      profileCompletion: userData.profileCompletion
    });
  } catch (error) {
    console.error('Get user stats error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};


// Search for users nearby
const searchNearbyUsers = async (req, res) => {
  try {
    const { longitude, latitude, maxDistance } = req.query;

    if (!longitude || !latitude) {
      return res.status(400).json({ success: false, message: 'Longitude and latitude are required.' });
    }

    const user = await UserData.findOne({ userId: req.user.id });
    if (user && user.location) {
      user.location.coordinates = [parseFloat(longitude), parseFloat(latitude)];
      await user.save();
    } else if (user) {
      user.location = { type: 'Point', coordinates: [parseFloat(longitude), parseFloat(latitude)] };
      await user.save();
    } else {
        const newUser_data = new UserData({
            userId: req.user.id,
            location: { type: 'Point', coordinates: [parseFloat(longitude), parseFloat(latitude)] }
        });
        await newUser_data.save();
    }

    // Find users near the current user
    const users = await UserData.find({
      userId: { $ne: req.user.id },
      location: {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [parseFloat(longitude), parseFloat(latitude)]
          },
          $maxDistance: parseInt(maxDistance) || 10000 // 10km in meters
        }
      }
    }).populate('userId', 'name email userId photoURL phone');

    res.json({ success: true, users });
  } catch (error) {
    console.error('Error searching nearby users:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get another user's profile by ID or userId string
const getOtherUserProfile = async (req, res) => {
  try {
    const { id } = req.params; // Can be MongoDB _id or custom userId string
    const requestingUserId = req.user && req.user.id ? req.user.id : null;

    console.log(`[HTTP] getOtherUserProfile: Fetching profile for ID: ${id}`);

    let user;
    let query = {};

    // Determine if 'id' is a MongoDB ObjectId or a custom userId string
    if (mongoose.Types.ObjectId.isValid(id)) {
      query = { _id: id };
    } else {
      query = { userId: id.toUpperCase() }; // Custom userId is typically uppercase
    }

    user = await User.findOne(query).select('-password');

    if (!user) {
      console.warn(`[HTTP] getOtherUserProfile: User not found for ID: ${id}`);
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    // Fetch or create associated UserData
    let userData = await UserData.findOne({ userId: user._id });
    if (!userData) {
      console.log(`[DB] No UserData found for ${user.userId}, creating new one.`);
      userData = new UserData({ userId: user._id });
      await userData.save();
    }

    // Determine friendship status between requesting user and target user
    let friendshipStatus = 'none';

    if (requestingUserId && requestingUserId.toString() === user._id.toString()) {
      friendshipStatus = 'self';
    } else if (requestingUserId) {
      // First check Friendship collection
      const friendship = await Friendship.findOne({
        $or: [
          { user1: requestingUserId, user2: user._id },
          { user1: user._id, user2: requestingUserId }
        ]
      });

      if (friendship) {
        if (friendship.status === 'accepted') friendshipStatus = 'friends';
        else if (friendship.status === 'blocked') friendshipStatus = 'blocked';
        else if (friendship.status === 'pending') {
          friendshipStatus = friendship.requestedBy && friendship.requestedBy.toString() === requestingUserId.toString() ? 'request_sent' : 'request_received';
        }
      } else {
        // Fall back to FriendRequest table (older flows)
        const existingRequest = await FriendRequest.findOne({
          $or: [
            { fromUserId: requestingUserId, toUserId: user._id, status: 'pending' },
            { fromUserId: user._id, toUserId: requestingUserId, status: 'pending' }
          ]
        });

        if (existingRequest) {
          friendshipStatus = existingRequest.fromUserId.toString() === requestingUserId.toString() ? 'request_sent' : 'request_received';
        }
      }
    }

    // Build response object mapping to integration guide
    const avatar = user.photoURL || userData.profilePicture || null;

    // Sensitive fields omitted for privacy when not friends
    const isSensitiveAllowed = friendshipStatus === 'friends' || friendshipStatus === 'self';

    const data = {
      _id: user._id,
      userId: user.userId,
      name: user.name,
      avatar: avatar,
      bio: userData?.bio || '',
      location: userData?.location || null,
      website: userData?.website || '',
      gender: user.gender || null,
      dateOfBirth: user.dateOfBirth ? new Date(user.dateOfBirth).toISOString().split('T')[0] : null,
      isOnline: !!userData?.isOnline,
      lastSeen: userData?.lastActive ? new Date(userData.lastActive).toISOString() : null,
      stats: userData?.stats || { postsCount: 0, followersCount: 0, followingCount: 0, profileCompletion: 0 },
      friendshipStatus: friendshipStatus
    };

    if (isSensitiveAllowed) {
      data.email = user.email || null;
      data.phone = user.phone || null;
    }

    console.log(`[HTTP] getOtherUserProfile: Successfully fetched profile for ${user.userId} (status: ${friendshipStatus})`);
    return res.json({ success: true, data });
  } catch (error) {
    console.error(`[HTTP] getOtherUserProfile error for ID ${req.params.id}:`, error);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
};

module.exports = {
  getUserProfile,
  updateUserProfile,
  uploadProfilePicture,
  getUserStats,
  searchUsers,
  searchNearbyUsers,
  getOtherUserProfile // Export the new function
};


// const UserData = require('../models/UserData');
// const User = require('../models/userModel');

// // In getUserProfile function - FIXED VERSION
// const getUserProfile = async (req, res) => {
//   try {
//     console.log('Get user profile request for userId:', req.user.id);

//     // First get the user with ALL fields including userId
//     const user = await User.findById(req.user.id).select('-password');
//     console.log('Full user data from database:', {
//       _id: user._id,
//       userId: user.userId, // This should exist
//       name: user.name,
//       email: user.email
//     });

//     let userData = await UserData.findOne({ userId: req.user.id });
    
//     console.log('Found userData:', userData);

//     if (!userData) {
//       // Create initial user data if doesn't exist
//       console.log('No userData found, creating new one...');
//       userData = new UserData({
//         userId: req.user.id
//       });
//       await userData.save();
//     }

//     // Return both user and userData with ALL fields including userId
//     const responseData = {
//       success: true,
//       user: {
//         id: user._id,
//         userId: user.userId, // CRITICAL: Make sure this is included
//         _id: user._id,
//         name: user.name,
//         email: user.email,
//         phone: user.phone,
//         dateOfBirth: user.dateOfBirth,
//         gender: user.gender,
//         photoURL: user.photoURL,
//         isPhoneVerified: user.isPhoneVerified,
//         isEmailVerified: user.isEmailVerified,
//         registrationComplete: user.registrationComplete
//       },
//       userData: userData
//     };

//     console.log('Returning profile data with userId:', responseData.user.userId);

//     res.json(responseData);
//   } catch (error) {
//     console.error('Get user profile error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };
// // Update user profile
// const updateUserProfile = async (req, res) => {
//   try {
//     const {
//       name,
//       dateOfBirth,
//       gender,
//       bio,
//       location,
//       website,
//       socialLinks,
//       interests,
//       preferences
//     } = req.body;

//     // Update basic user info
//     const userUpdate = {};
//     if (name) userUpdate.name = name;
//     if (dateOfBirth) userUpdate.dateOfBirth = dateOfBirth;
//     if (gender) userUpdate.gender = gender;

//     if (Object.keys(userUpdate).length > 0) {
//       await User.findByIdAndUpdate(req.user.id, userUpdate);
//     }

//     // Update or create user data
//     const userDataUpdate = {};
//     if (bio !== undefined) userDataUpdate.bio = bio;
//     if (location !== undefined) userDataUpdate.location = location;
//     if (website !== undefined) userDataUpdate.website = website;
//     if (socialLinks) userDataUpdate.socialLinks = socialLinks;
//     if (interests) userDataUpdate.interests = interests;
//     if (preferences) userDataUpdate.preferences = preferences;

//     const userData = await UserData.findOneAndUpdate(
//       { userId: req.user.id },
//       { $set: userDataUpdate },
//       { new: true, upsert: true, setDefaultsOnInsert: true }
//     ).populate('userId', 'name email phone dateOfBirth gender photoURL registrationComplete userId');

//     res.json({
//       success: true,
//       message: 'Profile updated successfully',
//       user: userData.userId,
//       userData: userData
//     });
//   } catch (error) {
//     console.error('Update user profile error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };

// // Upload profile picture
// const uploadProfilePicture = async (req, res) => {
//   try {
//     const { profilePicture } = req.body;

//     if (!profilePicture) {
//       return res.status(400).json({ success: false, message: 'Profile picture is required' });
//     }

//     const updatedUser = await User.findByIdAndUpdate(
//   req.user.id, 
//   { photoURL: profilePicture },
//   { new: true, select: 'name email phone dateOfBirth gender photoURL registrationComplete userId' }
// );

//     // Update userData profilePicture
//     const userData = await UserData.findOneAndUpdate(
//       { userId: req.user.id },
//       { $set: { profilePicture: profilePicture } },
//       { new: true, upsert: true, setDefaultsOnInsert: true }
//     ).populate('userId', 'name email phone dateOfBirth gender photoURL registrationComplete userId');

//     res.json({
//       success: true,
//       message: 'Profile picture updated successfully',
//       user: updatedUser, // Use the updated user object
//       userData: userData
//     });
//   } catch (error) {
//     console.error('Upload profile picture error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };
// // Get user stats
// const getUserStats = async (req, res) => {
//   try {
//  // If you're using population, make sure to include userId
// const userData = await UserData.findOne({ userId: req.user.id })
//   .populate('userId', 'name email userId phone dateOfBirth gender photoURL isPhoneVerified isEmailVerified registrationComplete');
    
//     if (!userData) {
//       return res.json({
//         success: true,
//         stats: {
//           postsCount: 0,
//           followersCount: 0,
//           followingCount: 0,
//           likesCount: 0
//         },
//         profileCompletion: 0
//       });
//     }

//     res.json({
//       success: true,
//       stats: userData.stats,
//       profileCompletion: userData.profileCompletion
//     });
//   } catch (error) {
//     console.error('Get user stats error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };

// // Search users
// const searchUsers = async (req, res) => {
//   try {
//     const { query } = req.query;
    
//     if (!query || query.length < 2) {
//       return res.status(400).json({ success: false, message: 'Search query must be at least 2 characters' });
//     }

//     const users = await User.find({
//       $or: [
//         { name: { $regex: query, $options: 'i' } },
//         { email: { $regex: query, $options: 'i' } }
//       ],
//       _id: { $ne: req.user.id } // Exclude current user
//     }).select('name email photoURL').limit(20);

//     res.json({
//       success: true,
//       users: users
//     });
//   } catch (error) {
//     console.error('Search users error:', error);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// };

// module.exports = {
//   getUserProfile,
//   updateUserProfile,
//   uploadProfilePicture,
//   getUserStats,
//   searchUsers
// };