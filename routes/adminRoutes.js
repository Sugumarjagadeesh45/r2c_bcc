const express = require("express");
const router = express.Router();
const notificationController = require("../controllers/notificationController");
const auth = require("../middleware/auth");
const admin = require("../middleware/admin");

/**
 * @route   POST /api/admin/notify
 * @desc    Send a notification to a specific user
 * @access  Admin
 */
router.post("/notify", auth, admin, notificationController.sendUserNotification);


/**
 * @route   POST /api/admin/broadcast
 * @desc    Send a broadcast notification to all users
 * @access  Admin
 */
router.post("/broadcast", auth, admin, notificationController.sendAdminBroadcast);

module.exports = router;
