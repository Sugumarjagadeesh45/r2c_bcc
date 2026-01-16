// D:\reals2chat_backend-main\controllers\testFCMController.js
const mongoose = require('mongoose'); // ADD THIS LINE
const fcmService = require('../services/fcmService');
const FCMToken = require('../models/FCMToken');
const User = require('../models/userModel');

exports.sendTestNotification = async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user._id;
    
    console.log(`[Test-Notification] Sending test notification to user: ${userId}`);
    console.log(`[Test-Notification] From user: ${currentUserId}`);
    
    // Try to find user by userId string first, then by ObjectId
    let targetUser;
    if (mongoose.Types.ObjectId.isValid(userId)) {
      targetUser = await User.findById(userId);
    } else {
      targetUser = await User.findOne({ userId: userId });
    }
    
    if (!targetUser) {
      console.log(`[Test-Notification] ❌ User not found: ${userId}`);
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const targetUserId = targetUser._id;
    
    // Check if user has FCM token
    const tokens = await FCMToken.find({ userId: targetUserId });
    
    if (tokens.length === 0) {
      console.log(`[Test-Notification] ❌ User ${userId} (${targetUserId}) has no FCM tokens registered`);
      return res.status(400).json({
        success: false,
        message: 'User has no FCM tokens registered'
      });
    }
    
    console.log(`[Test-Notification] ✅ Found ${tokens.length} token(s) for user ${userId}`);
    
    // Get current user info
    const currentUser = await User.findById(currentUserId);
    
    if (!currentUser) {
      return res.status(404).json({
        success: false,
        message: 'Current user not found'
      });
    }
    
    // Validate tokens first
    const validTokens = tokens.filter(token => {
      // Check if token looks like a valid FCM token
      const isValid = token.token && token.token.length > 100 && 
                     (token.token.includes(':APA91b') || token.token.includes('fcm'));
      if (!isValid) {
        console.log(`[Test-Notification] ⚠️ Invalid FCM token format for user ${userId}`);
      }
      return isValid;
    });
    
    if (validTokens.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid FCM tokens found for user'
      });
    }
    
    // Send test notification
    const testPayload = {
      notification: {
        title: 'Test Notification',
        body: `This is a test notification from ${currentUser.name || 'the system'}`,
      },
      data: {
        type: 'test',
        senderId: currentUserId.toString(),
        senderName: currentUser.name || 'Test User',
        message: 'FCM is working correctly!',
        timestamp: new Date().toISOString()
      }
    };
    
    console.log(`[Test-Notification] 📤 Sending test payload`);
    console.log(`[Test-Notification] First token: ${validTokens[0].token.substring(0, 50)}...`);
    
    await fcmService.sendToUser(targetUserId, testPayload);
    
    res.json({
      success: true,
      message: 'Test notification sent successfully',
      tokenCount: validTokens.length,
      tokenPreview: validTokens[0].token.substring(0, 20) + '...'
    });
    
  } catch (error) {
    console.error('[Test-Notification] ❌ Error:', error);
    res.status(500).json({
      success: false,
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};