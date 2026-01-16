const express = require('express');
const router = express.Router();
const friendsController = require('../controllers/FriendsController');
const protect = require('../middleware/auth');

// Get all friends
router.get('/', protect, friendsController.getFriends);

// Get friend suggestions (age-based)
router.get('/suggestions', protect, friendsController.getFriendSuggestions);

// Search users for adding as friends
router.get('/search', protect, friendsController.searchUsersForFriends);

// Send friend request
router.post('/send-request', protect, friendsController.sendFriendRequest);

// Get pending friend requests
router.get('/requests/pending', protect, friendsController.getPendingRequests);

// Get sent friend requests
router.get('/requests/sent', protect, friendsController.getSentRequests);

// Accept friend request
router.post('/requests/:requestId/accept', protect, friendsController.acceptFriendRequest);

// Reject friend request
router.post('/requests/:requestId/reject', protect, friendsController.rejectFriendRequest);

// Remove friend (unfriend)
router.delete('/:friendId', protect, friendsController.removeFriend);

// Block user
router.post('/block/:userId', protect, friendsController.blockUser);

module.exports = router;