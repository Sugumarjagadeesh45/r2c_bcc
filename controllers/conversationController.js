const mongoose = require('mongoose');
const ConversationMetadata = require('../models/conversationMetadataModel');

exports.updateMetadata = async (req, res) => {
  const { otherUserId } = req.params;
  const userId = req.user._id;
  const { isPinned, isBlocked, customRingtone, isFavorite } = req.body;

  if (!mongoose.Types.ObjectId.isValid(otherUserId)) {
    return res.status(400).json({ success: false, message: 'Invalid otherUserId provided.' });
  }

  try {
    let metadata = await ConversationMetadata.findOne({
      userId,
      otherUserId,
    });

    if (!metadata) {
      metadata = new ConversationMetadata({
        userId,
        otherUserId,
      });
    }

    if (isPinned !== undefined) {
      metadata.isPinned = isPinned;
    }
    if (isBlocked !== undefined) {
      metadata.isBlocked = isBlocked;
    }
    if (customRingtone !== undefined) {
      metadata.customRingtone = customRingtone;
    }
    if (isFavorite !== undefined) {
      metadata.isFavorite = isFavorite;
    }

    await metadata.save();

    res.status(200).json({ success: true, data: metadata });
  } catch (error) {
    console.error('Error updating conversation metadata:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
};
