const UserLocation = require('../models/UserLocation');

/**
 * Updates user online status in UserLocation collection
 * Call this from your Socket.IO 'connection' and 'disconnect' events
 * @param {string} userId - The user's ID
 * @param {boolean} isOnline - Online status
 */
const updateUserStatus = async (userId, isOnline) => {
  try {
    const update = {
      isOnline,
      updatedAt: new Date()
    };
    
    if (!isOnline) {
      update.lastSeen = new Date();
    }

    // Only update if the user exists in UserLocation (has shared location)
    await UserLocation.findOneAndUpdate(
      { userId },
      update
    );
  } catch (error) {
    console.error(`[NearbyService] Error updating status for user ${userId}:`, error);
  }
};

module.exports = { updateUserStatus };