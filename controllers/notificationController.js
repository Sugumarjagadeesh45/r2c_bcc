const fcmService = require('../services/fcmService');
const User = require('../models/userModel');

/**
 * @route   POST /api/admin/notify
 * @desc    Send a notification to a specific user
 * @access  Admin
 */
exports.sendUserNotification = async (req, res) => {
  const { userId, title, body, data } = req.body;

  if (!userId || !title || !body) {
    return res.status(400).json({ message: 'userId, title, and body are required.' });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const notificationPayload = {
      notification: {
        title,
        body,
      },
      data: {
        type: 'ADMIN_NOTIFICATION',
        ...data,
      },
    };

    await fcmService.sendToUser(userId, notificationPayload);

    res.status(200).json({ success: true, message: 'Notification sent successfully.' });
  } catch (error) {
    console.error('Error sending admin notification:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
};

/**
 * @route   POST /api/admin/broadcast
 * @desc    Send a broadcast notification to all users
 * @access  Admin
 */
exports.sendAdminBroadcast = async (req, res) => {
    const { title, body, data } = req.body;

    if (!title || !body) {
        return res.status(400).json({ message: "Title and body are required." });
    }

    try {
        const users = await User.find({}, '_id');
        const userIds = users.map(user => user._id);

        if (userIds.length > 0) {
            const notificationPayload = {
              notification: {
                title,
                body,
              },
              data: {
                type: 'ADMIN_BROADCAST',
                ...data,
              },
            };
            await fcmService.sendToUsers(userIds, notificationPayload);
        }

        res.status(200).json({ message: "Admin notification sent to all users." });
    } catch (error) {
        console.error("Error sending admin broadcast:", error);
        res.status(500).json({ message: "Internal server error." });
    }
};

/**
 * @route   POST /api/notifications/register-token
 * @desc    Register an FCM token for the logged-in user
 * @access  Private
 */
exports.registerToken = async (req, res) => {
  try {
    const { token } = req.body;
    // Ensure req.user exists (populated by auth middleware)
    const userId = req.user ? (req.user.id || req.user._id) : null;

    if (!userId) {
      return res.status(401).json({ message: 'Unauthorized. User not found in request.' });
    }

    if (!token) {
      return res.status(400).json({ message: 'Token is required' });
    }

    // Add token to user's fcmTokens array if it doesn't exist ($addToSet prevents duplicates)
    await User.findByIdAndUpdate(userId, {
      $addToSet: { fcmTokens: token }
    });

    console.log(`[DB] ✅ FCM Token saved for user: ${userId}`);
    res.status(200).json({ success: true, message: 'Token registered successfully' });
  } catch (error) {
    console.error('[DB] ❌ Error registering token:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

/**
 * @route   POST /api/notifications/remove-token
 * @desc    Remove an FCM token (e.g., on logout)
 * @access  Private
 */
exports.removeToken = async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user ? (req.user.id || req.user._id) : null;

    if (!userId) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    await User.findByIdAndUpdate(userId, {
      $pull: { fcmTokens: token }
    });

    console.log(`[DB] 🗑️ FCM Token removed for user: ${userId}`);
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('[DB] ❌ Error removing token:', error);
    res.status(500).json({ message: 'Server error' });
  }
};
