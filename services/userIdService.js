const Counter = require('../models/counterModel');
const User = require('../models/userModel');

/**
 * Service for handling unique user ID generation and validation.
 */
class UserIdService {
  /**
   * Atomically generates a unique user ID in the format: R2CYYYYMMDDNNN
   * @returns {Promise<string>} A unique user ID.
   */
  static async generateUserId() {
    const now = new Date();
    const year = now.getFullYear();
    const month = (now.getMonth() + 1).toString().padStart(2, '0');
    const day = now.getDate().toString().padStart(2, '0');
    const dateStr = `${year}${month}${day}`;
    const counterId = `userId_${dateStr}`;

    // Atomically find the counter for today and increment its sequence value.
    // If the counter doesn't exist, it will be created with sequence_value = 1.
    const counter = await Counter.findByIdAndUpdate(
      counterId,
      { $inc: { sequence_value: 1 } },
      { new: true, upsert: true }
    );

    const sequenceStr = counter.sequence_value.toString().padStart(3, '0');
    return `R2C${dateStr}${sequenceStr}`;
  }

  /**
   * Validates the format of a custom user ID.
   * @param {string} userId The user ID to validate.
   * @returns {boolean} True if the format is valid, false otherwise.
   */
  static validateCustomUserId(userId) {
    if (!userId || typeof userId !== 'string') {
      return false;
    }
    // Must be at least 6 characters
    if (userId.length < 6) {
      return false;
    }
    // Must be alphanumeric
    if (!/^[a-zA-Z0-9]+$/.test(userId)) {
      return false;
    }
    // Must contain at least one number
    if (!/\d/.test(userId)) {
      return false;
    }
    return true;
  }

  /**
   * Checks if a given user ID is already in use.
   * @param {string} userId The user ID to check.
   * @returns {Promise<boolean>} True if the ID is available, false otherwise.
   */
  static async isUserIdAvailable(userId) {
    if (!userId) {
      return false;
    }
    const existingUser = await User.findOne({ 
      userId: userId.toUpperCase().trim() 
    });
    return !existingUser;
  }
}

module.exports = UserIdService;
