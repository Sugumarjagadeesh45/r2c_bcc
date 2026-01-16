const express = require('express');
const router = express.Router();
const userDataController = require('../controllers/userDataController');
const friendsController = require('../controllers/FriendsController');
const protect = require('../middleware/auth');
const upload = require('../middleware/upload');

// User data routes
router.get('/profile', protect, userDataController.getUserProfile);
router.put('/profile', protect, userDataController.updateUserProfile);
router.post('/profile-picture', protect, upload.single('profileImage'), userDataController.uploadProfilePicture);
router.get('/stats', protect, userDataController.getUserStats);
router.get('/search', protect, userDataController.searchUsers);
router.get('/nearby', protect, userDataController.searchNearbyUsers);
router.get('/profile/:id', protect, userDataController.getOtherUserProfile); // New route to fetch any user's profile

module.exports = router;




// const express = require('express');
// const router = express.Router();
// const userDataController = require('../controllers/userDataController');
// const friendsController = require('../controllers/FriendsController');
// const protect = require('../middleware/auth');

// // User data routes
// router.get('/profile', protect, userDataController.getUserProfile);
// router.put('/profile', protect, userDataController.updateUserProfile);
// router.post('/profile-picture', protect, userDataController.uploadProfilePicture);
// router.get('/stats', protect, userDataController.getUserStats);
// router.get('/search', protect, userDataController.searchUsers);

// // Friends routes
// router.get('/friends/suggestions', protect, friendsController.getFriendSuggestions);
// router.post('/friends/request', protect, friendsController.sendFriendRequest);
// router.get('/friends', protect, friendsController.getFriends);

// module.exports = router;
