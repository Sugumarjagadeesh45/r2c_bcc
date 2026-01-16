const express = require("express");
const router = express.Router();
const fcmTokenController = require("../controllers/fcmTokenController");
const auth = require("../middleware/auth");

/**
 * @route   POST /api/notifications/register-token
 * @desc    Register or update an FCM token for a user
 * @access  Private
 */
router.post("/register-token", auth, fcmTokenController.registerToken);

/**
 * @route   GET /api/notifications/test-fcm
 * @desc    Test FCM configuration for current user
 * @access  Private
 */
router.get("/test-fcm", auth, fcmTokenController.testFCM);

module.exports = router;







// const express = require("express");
// const router = express.Router();
// const fcmTokenController = require("../controllers/fcmTokenController");
// const auth = require("../middleware/auth");

// /**
//  * @route   POST /api/notifications/register-token
//  * @desc    Register or update an FCM token for a user
//  * @access  Private
//  */
// router.post("/register-token", auth, fcmTokenController.registerToken);

// module.exports = router;
