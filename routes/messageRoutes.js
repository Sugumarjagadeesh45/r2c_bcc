const express = require("express");
const router = express.Router();
const messageController = require("../controllers/messageController");
const auth = require("../middleware/auth");

/**
 * @route   POST /api/messages/send
 * @desc    Send a new message to another user
 * @access  Private
 */
router.post("/messages/send", auth, messageController.sendMessage);
router.post("/chat/send", auth, messageController.sendChatMessage);

/**
 * @route   GET /api/messages/:otherUserId
 * @desc    Get message history with another user
 * @access  Private
 */
router.get("/messages/:otherUserId", auth, messageController.getMessages);


module.exports = router;
