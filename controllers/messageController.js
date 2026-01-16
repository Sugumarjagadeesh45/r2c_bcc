const mongoose = require('mongoose');
const Message = require('../models/messageModel');
const Conversation = require('../models/conversationModel');
const User = require('../models/userModel');
const fcmService = require('../services/fcmService');

/**
 * @route   POST /api/chat/send
 * @desc    Send a new chat message to another user
 * @access  Private
 */
exports.sendChatMessage = async (req, res) => {
  const { to, message } = req.body;
  const senderId = req.user._id;

  if (!to || !message) {
    return res.status(400).json({ message: 'Recipient (to) and message are required.' });
  }

  try {
    let recipient;
    if (mongoose.Types.ObjectId.isValid(to)) {
      recipient = await User.findById(to);
    } else {
      recipient = await User.findOne({ userId: to });
    }

    if (!recipient) {
      return res.status(404).json({ message: 'Recipient not found.' });
    }

    req.body.recipientId = recipient._id;
    req.body.text = message;

    return exports.sendMessage(req, res);
  } catch (error) {
    console.error('Error sending chat message:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
};

/**
 * @route   POST /api/messages/send
 * @desc    Send a new message to another user
 * @access  Private
 */
exports.sendMessage = async (req, res) => {
  const { recipientId, text, attachment } = req.body;
  const senderId = req.user._id;
  const senderName = req.user.name || 'Unknown User';
  const senderPhotoURL = req.user.photoURL;

  if (!recipientId || (!text && !attachment)) {
    console.warn(`[HTTP] sendMessage: Missing recipientId or message content for sender ${senderId}`);
    return res.status(400).json({ success: false, message: 'Recipient ID and text or attachment are required.' });
  }

  console.log(`[HTTP] Message received from ${senderId} (HTTP). Content: ${text || attachment?.type}`);

  try {
    let conversation = await Conversation.findOne({
      participants: { $all: [senderId, recipientId] },
    });

    if (!conversation) {
      conversation = new Conversation({
        participants: [senderId, recipientId],
      });
      await conversation.save();
      console.log(`[DB] New conversation ${conversation._id} created between ${senderId} and ${recipientId} (HTTP)`);
    }

    const newMessage = new Message({
      conversationId: conversation._id,
      sender: senderId,
      recipient: recipientId,
      text: text,
      attachment: attachment,
      status: 'sent', // Initial status
    });
    await newMessage.save();
    console.log(`[DB] Message ${newMessage._id} stored. Status: ${newMessage.status} (HTTP)`);

    // Prepare message object for response, populating sender details
    const fullMessage = {
      ...newMessage.toObject(),
      sender: {
        _id: senderId,
        name: senderName,
        avatar: senderPhotoURL,
      },
      conversationId: conversation._id.toString()
    };

    // Trigger FCM notification to recipient
    const recipientUser = await User.findById(recipientId); // Fetch recipient user data for name
    if (recipientUser) {
      fcmService.sendNewMessageNotification(
        recipientId,
        req.user, // Sender object
        newMessage,
        conversation._id // Conversation ID
      );
      console.log(`[FCM] Notification triggered for recipient ${recipientId} for message ${newMessage._id} (HTTP)`);
    } else {
      console.warn(`[FCM] Recipient user ${recipientId} not found, cannot send FCM notification (HTTP).`);
    }

    res.status(201).json({ success: true, message: 'Message sent successfully.', data: fullMessage });

  } catch (error) {
    console.error(`[HTTP] Error sending message for ${senderId}:`, error);
    res.status(500).json({ success: false, message: 'Internal server error.' });
  }
};


/**
 * @route   GET /api/messages/:otherUserId
 * @desc    Get message history with another user
 * @access  Private
 */
exports.getMessages = async (req, res) => {
    let currentUserId = req.user._id;
    let otherUserId = req.params.otherUserId;

    console.log(`[HTTP] getMessages: Fetching messages for user ${currentUserId} with ${otherUserId}`);

    try {
      // If otherUserId is not a valid ObjectId, try to find the user by userId string
      if (!mongoose.Types.ObjectId.isValid(otherUserId)) {
        const otherUser = await User.findOne({ userId: otherUserId });
        if (otherUser) {
          otherUserId = otherUser._id;
          console.log(`[HTTP] getMessages: Resolved otherUserId string '${req.params.otherUserId}' to ObjectId '${otherUserId}'`);
        } else {
          console.warn(`[HTTP] getMessages: Invalid or unknown otherUserId provided: ${req.params.otherUserId}`);
          return res.status(400).json({ success: false, message: 'Invalid or unknown otherUserId provided.' });
        }
      }

        const conversation = await Conversation.findOne({
            participants: { $all: [currentUserId, otherUserId] },
        });

        if (!conversation) {
            console.log(`[HTTP] getMessages: No conversation found between ${currentUserId} and ${otherUserId}. Returning empty array.`);
            return res.status(200).json({ success: true, data: [] });
        }

        const messages = await Message.find({ conversationId: conversation._id })
        .sort({ createdAt: 'asc' }) // Ascending order as frontend expects
        .populate('sender', '_id name photoURL userId') // Include userId and photoURL
        .populate('recipient', '_id name photoURL userId'); // Include userId and photoURL

        console.log(`[HTTP] getMessages: Found ${messages.length} messages for conversation ${conversation._id}`);

        res.status(200).json({ success: true, data: messages });
    } catch (error) {
        console.error(`[HTTP] Error getting messages for user ${currentUserId} with ${otherUserId}:`, error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
}
