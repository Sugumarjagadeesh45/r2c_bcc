// // D:\good_r2c-main\services\fcmService.js
// const firebaseConfig = require("../config/firebase");
// const admin = firebaseConfig.admin;
// const FCMToken = require("../models/FCMToken");

// // Add validation function
// const isValidFCMToken = (token) => {
//   if (!token) {
//     console.log('[FCM-Validation] ❌ Token is null/undefined');
//     return false;
//   }
  
//   if (typeof token !== 'string') {
//     console.log('[FCM-Validation] ❌ Token is not a string:', typeof token);
//     return false;
//   }
  
//   if (token.length < 30) {
//     console.log(`[FCM-Validation] ❌ Token too short: ${token.length} chars`);
//     return false;
//   }
  
//   const hasValidPattern = token.includes(':APA91b') || 
//                          token.startsWith('fcm') ||
//                          token.includes('AAAA') ||
//                          token.includes('fk3Kp8DjT0yf');
  
//   if (!hasValidPattern) {
//     console.log(`[FCM-Validation] ⚠️ Token doesn't match FCM pattern: ${token.substring(0, 30)}...`);
//     console.log(`[FCM-Validation] ⚠️ Allowing token for testing purposes`);
//   }
  
//   console.log(`[FCM-Validation] ✅ Token appears valid (${token.length} chars)`);
//   return true;
// };

// // Modify sendNotification function
// const sendNotification = async (tokens, payload) => {
//   if (!tokens || tokens.length === 0) {
//     console.log('[FCM-Service] ❌ No tokens to send notification to');
//     return;
//   }

//   console.log('\n[FCM-Service] ==========================================');
//   console.log('[FCM-Service] 🚀 SENDING NOTIFICATION');
//   console.log('[FCM-Service] Number of tokens:', tokens.length);
  
//   // DEBUG: Check Firebase admin
//   console.log('[FCM-Service] 🔍 Checking Firebase admin...');
//   console.log('[FCM-Service] Admin exists:', !!admin);
//   console.log('[FCM-Service] Admin type:', typeof admin);
  
//   if (!admin) {
//     console.log('[FCM-Service] ❌ Firebase admin is null/undefined');
//     console.log('[FCM-Service] Re-initializing Firebase...');
//     const firebaseConfig = require("../config/firebase");
//     admin = firebaseConfig.getAdmin(); // Try to get admin again
//     console.log('[FCM-Service] Admin after re-init:', !!admin);
//   }
  
//   // Continue with your existing code...
  
//   // Validate each token
//   const validTokens = [];
//   const invalidTokens = [];
  
//   tokens.forEach(token => {
//     if (isValidFCMToken(token)) {
//       validTokens.push(token);
//     } else {
//       invalidTokens.push(token);
//     }
//   });
  
//   if (validTokens.length === 0) {
//     console.log('[FCM-Service] ❌ No valid tokens to send notification to');
//     if (invalidTokens.length > 0) {
//       console.log('[FCM-Service] Invalid tokens found:', invalidTokens.length);
//     }
//     return;
//   }
  
//   console.log(`[FCM-Service] ✅ Valid tokens: ${validTokens.length}, Invalid: ${invalidTokens.length}`);
//   console.log('[FCM-Service] First valid token:', validTokens[0].substring(0, 50) + '...');
//   console.log('[FCM-Service] ==========================================\n');

//   try {
//     // Check if admin.messaging is available
//     if (!admin.messaging) {
//       console.error('[FCM-Service] ❌ admin.messaging is not available');
//       console.log('[FCM-Service] Firebase apps:', admin.apps.length);
//       return;
//     }

//     const messagePayload = {
//       tokens: validTokens,
//       notification: payload.notification,
//       data: payload.data,
//       android: {
//         priority: "high",
//         notification: {
//           sound: "default",
//           channelId: "chat_messages",
//           priority: "max",
//           visibility: "public",
//         }
//       },
//       apns: {
//         payload: {
//           aps: {
//             sound: "default",
//             badge: 1,
//             contentAvailable: true,
//           }
//         }
//       }
//     };

//     const response = await admin.messaging().sendEachForMulticast(messagePayload);

//     console.log('[FCM-Service] ✅ FCM Response Success Count:', response.successCount);
    
//     if (response.successCount === 0 && response.failureCount > 0) {
//       console.log('[FCM-Service] ❌ FCM Response Failure Count:', response.failureCount);
//     }

//     const tokensToRemove = [];
//     response.responses.forEach((result, index) => {
//       const error = result.error;
//       if (error) {
//         console.error('[FCM-Service] ❌ Failure sending notification:', {
//           token: validTokens[index].substring(0, 20) + '...',
//           error: error.message,
//           code: error.code
//         });
        
//         if (
//           error.code === "messaging/invalid-registration-token" ||
//           error.code === "messaging/registration-token-not-registered" ||
//           error.code === "messaging/invalid-argument"
//         ) {
//           tokensToRemove.push(validTokens[index]);
//         }
//       }
//     });

//     if (tokensToRemove.length > 0) {
//       console.log('[FCM-Service] 🗑️ Removing invalid tokens:', tokensToRemove.length);
//       await FCMToken.deleteMany({ token: { $in: tokensToRemove } });
//     }
//   } catch (error) {
//     console.error('[FCM-Service] ❌ Error in sendNotification:', error.message);
//     console.error('[FCM-Service] Error details:', error);
//   }
// };

// const sendToUser = async (userId, payload) => {
//   try {
//     console.log(`[FCM-Service] 🔍 Fetching tokens for user: ${userId}`);
//     const userTokens = await FCMToken.find({ userId }).select("token -_id");
    
//     if (userTokens.length === 0) {
//       console.log(`[FCM-Service] ❌ No FCM tokens found for user ${userId}`);
//       return { success: false, error: 'No tokens found for user' };
//     }
    
//     const tokens = userTokens.map((t) => t.token);
//     console.log(`[FCM-Service] ✅ Found ${tokens.length} tokens. Sending notification...`);
//     return await sendNotification(tokens, payload);
    
//   } catch (error) {
//     console.error(`[FCM-Service] ❌ Failed to fetch tokens for user ${userId}:`, error.message);
//     return { success: false, error: error.message };
//   }
// };

// const sendNewMessageNotification = async (recipientId, sender, message, conversationId) => {
//   console.log(`[FCM-Service] 💬 Preparing notification for ${recipientId}`);
  
//   const payload = {
//     notification: {
//       title: sender.name || 'New Message',
//       body: message.text || (message.attachment ? 'Sent an attachment' : 'Sent a message'),
//     },
//     data: {
//       type: 'chat_message',
//       otherUserId: sender._id.toString(),
//       otherUserName: sender.name || 'Unknown User',
//       otherUserPhotoURL: sender.photoURL || '',
//       conversationId: conversationId.toString(),
//       messageId: message._id.toString(),
//       text: message.text || '',
//       timestamp: new Date().toISOString()
//     },
//   };
  
//   return await sendToUser(recipientId, payload);
// };

// const sendFriendRequestNotification = async (recipientId, sender) => {
//   const payload = {
//     notification: {
//       title: 'New Friend Request',
//       body: `${sender.name || 'Someone'} wants to be your friend`,
//     },
//     data: {
//       type: 'FRIEND_REQUEST',
//       senderId: sender._id.toString(),
//       senderName: sender.name || 'Unknown User'
//     },
//   };
//   return await sendToUser(recipientId, payload);
// };

// const sendFriendRequestAcceptedNotification = async (originalSenderId, acceptor) => {
//   const payload = {
//     notification: {
//       title: 'Friend Request Accepted',
//       body: `${acceptor.name || 'Someone'} accepted your friend request`,
//     },
//     data: {
//       type: 'FRIEND_REQUEST_ACCEPTED',
//       acceptorId: acceptor._id.toString(),
//       acceptorName: acceptor.name || 'Unknown User'
//     }
//   };
//   return await sendToUser(originalSenderId, payload);
// };

// module.exports = {
//   sendNotification,
//   sendToUser,
//   sendToUsers: sendToUser, 
//   sendNewMessageNotification,
//   sendFriendRequestNotification,
//   sendFriendRequestAcceptedNotification,
// };

























// services/fcmService.js
const admin = require("../config/firebase");
const FCMToken = require("../models/FCMToken");

/* ---------------- TOKEN VALIDATION ---------------- */

const isValidFCMToken = (token) => {
  if (!token || typeof token !== "string") return false;
  if (token.length < 30) return false;
  return true;
};

/* ---------------- SEND NOTIFICATION ---------------- */

const sendNotification = async (tokens, payload) => {
  if (!tokens || tokens.length === 0) {
    console.log("[FCM] ❌ No tokens");
    return;
  }

  if (!admin.apps || admin.apps.length === 0) {
    console.error("[FCM] ❌ Firebase not initialized");
    return;
  }

  const validTokens = tokens.filter(isValidFCMToken);

  if (validTokens.length === 0) {
    console.log("[FCM] ❌ No valid tokens");
    return;
  }

  const message = {
    tokens: validTokens,

    notification: payload.notification,

    data: payload.data,

    android: {
      priority: "high",
      notification: {
        channelId: "chat_messages",
        sound: "default",
        visibility: "public",
        priority: "max",
      },
    },

    apns: {
      payload: {
        aps: {
          sound: "default",
          badge: 1,
        },
      },
    },
  };

  try {
    const response = await admin
      .messaging()
      .sendEachForMulticast(message);

    console.log("[FCM] ✅ Success:", response.successCount);
    console.log("[FCM] ❌ Failed:", response.failureCount);

    const invalidTokens = [];

    response.responses.forEach((res, index) => {
      if (res.error) {
        console.error(
          "[FCM] ❌ Token error:",
          res.error.code
        );

        if (
          res.error.code === "messaging/invalid-registration-token" ||
          res.error.code === "messaging/registration-token-not-registered"
        ) {
          invalidTokens.push(validTokens[index]);
        }
      }
    });

    if (invalidTokens.length > 0) {
      await FCMToken.deleteMany({ token: { $in: invalidTokens } });
      console.log("[FCM] 🗑️ Removed invalid tokens:", invalidTokens.length);
    }
  } catch (err) {
    console.error("[FCM] ❌ Send error:", err.message);
  }
};

/* ---------------- SEND TO USER ---------------- */

const sendToUser = async (userId, payload) => {
  try {
    const tokens = await FCMToken.find({ userId }).select("token -_id");

    if (!tokens.length) {
      console.log(`[FCM] ❌ No tokens for user ${userId}`);
      return;
    }

    const tokenList = tokens.map((t) => t.token);
    await sendNotification(tokenList, payload);
  } catch (err) {
    console.error("[FCM] ❌ DB error:", err.message);
  }
};

/* ---------------- CHAT MESSAGE ---------------- */

const sendNewMessageNotification = async (
  recipientId,
  sender,
  message,
  conversationId
) => {
  const payload = {
    notification: {
      title: sender.name || "New Message",
      body: message.text || "New message received",
    },
    data: {
      type: "CHAT_MESSAGE",
      conversationId: conversationId.toString(),
      senderId: sender._id.toString(),
      senderName: sender.name || "",
      messageId: message._id.toString(),
      text: message.text || "",
    },
  };

  await sendToUser(recipientId, payload);
};

/* ---------------- FRIEND REQUEST ---------------- */

const sendFriendRequestNotification = async (recipientId, sender) => {
  const payload = {
    notification: {
      title: "Friend Request",
      body: `${sender.name} sent you a friend request`,
    },
    data: {
      type: "FRIEND_REQUEST",
      senderId: sender._id.toString(),
    },
  };

  await sendToUser(recipientId, payload);
};

const sendFriendRequestAcceptedNotification = async (recipientId, acceptor) => {
  const payload = {
    notification: {
      title: "Request Accepted",
      body: `${acceptor.name} accepted your request`,
    },
    data: {
      type: "FRIEND_REQUEST_ACCEPTED",
      acceptorId: acceptor._id.toString(),
    },
  };

  await sendToUser(recipientId, payload);
};

module.exports = {
  sendNotification,
  sendToUser,
  sendNewMessageNotification,
  sendFriendRequestNotification,
  sendFriendRequestAcceptedNotification,
};
