const express = require('express');
const router = express.Router();
const conversationController = require('../controllers/conversationController');
const auth = require('../middleware/auth');

router.put(
  '/conversations/:otherUserId/metadata',
  auth,
  conversationController.updateMetadata
);

module.exports = router;
