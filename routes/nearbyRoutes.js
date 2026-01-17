const express = require('express');
const router = express.Router();
const nearbyController = require('../controllers/nearbyController');
const protect = require('../middleware/auth');

// Update location (called periodically or on movement)
router.post('/location', protect, nearbyController.updateLocation);

// Get nearby users
router.get('/users', protect, nearbyController.getNearbyUsers);

module.exports = router;