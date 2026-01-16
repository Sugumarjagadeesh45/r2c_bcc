// D:\reals2chat_backend-main\services\socket.js - FIXED VERSION (CommonJS)
// const socketio = require('socket.io');
// const jwt = require('jsonwebtoken');
// const UserData = require('../models/UserData');
// const User = require('../models/userModel');
// const Message = require('../models/messageModel');
// const Conversation = require('../models/conversationModel');
// const Friendship = require('../models/Friendship');
// const fcmService = require('./fcmService');

// const onlineUsers = new Map();

// const initSocket = (server) => {
//   const io = socketio(server, {
//     cors: {
//       origin: '*',
//       methods: ['GET', 'POST'],
//       credentials: true
//     },
//     transports: ['websocket', 'polling']
//   });

//   console.log(`[Socket] 🔵 Socket.IO server initialized with CORS: *`);

//   io.use(async (socket, next) => {
//     console.log(`[Socket] 🔐 Attempting to authenticate socket connection...`);
//     const token = socket.handshake.query.token;
    
//     if (!token) {
//       console.log('[Socket] ❌ Authentication error: No token provided');
//       return next(new Error('Authentication error: No token provided'));
//     }
    
//     try {
//       console.log(`[Socket] 🔐 Verifying JWT token...`);
//       const decoded = jwt.verify(token, process.env.JWT_SECRET);
//       console.log(`[Socket] 🔐 Token decoded successfully for user ID: ${decoded.id}`);
      
//       socket.user = await User.findById(decoded.id);
//       if (!socket.user) {
//         console.log('[Socket] ❌ Authentication error: User not found for token');
//         return next(new Error('Authentication error: User not found'));
//       }
      
//       console.log(`[Socket] ✅ Authentication successful for user: ${socket.user.userId} (${socket.user.id})`);
//       next();
//     } catch (error) {
//       console.error('[Socket] ❌ JWT verification error:', error.message);
//       return next(new Error('Authentication error: Invalid token'));
//     }
//   });

//   io.on('connection', async (socket) => {
//     console.log(`\n[Socket] ==========================================`);
//     console.log(`[Socket] ✅ User connected: ${socket.user.userId} (${socket.user.id})`);
//     console.log(`[Socket] 📍 Socket ID: ${socket.id}`);
//     console.log(`[Socket] ==========================================\n`);
    
//     // Add user to online users map
//     onlineUsers.set(socket.user.id.toString(), socket.id);
//     console.log(`[Socket] 👥 Total online users: ${onlineUsers.size}`);
//     console.log(`[Socket] 👥 Online users map:`, Array.from(onlineUsers.entries()));

//     try {
//       // Update or create userData
//       let userData = await UserData.findOne({ userId: socket.user.id });
//       if (userData) {
//         userData.isOnline = true;
//         // Ensure location object is valid
//         if (!userData.location || !userData.location.type || !userData.location.coordinates || userData.location.coordinates.length !== 2) {
//           userData.location = {
//             type: 'Point',
//             coordinates: [0, 0]
//           };
//         }
//         await userData.save();
//         console.log(`[DB] ✅ UserData for ${socket.user.userId} updated: isOnline = true`);
//       } else {
//         // Create new UserData if it doesn't exist
//         userData = new UserData({ 
//           userId: socket.user.id, 
//           isOnline: true,
//           location: {
//             type: 'Point',
//             coordinates: [0, 0]
//           }
//         });
//         await userData.save();
//         console.log(`[DB] ✅ New UserData created for ${socket.user.userId} with isOnline = true`);
//       }

//       // Broadcast online status to friends
//       const friendships = await Friendship.find({
//         $or: [{ user1: socket.user.id, status: 'accepted' }, { user2: socket.user.id, status: 'accepted' }],
//       });

//       const friendIds = friendships.map((friendship) => {
//         return friendship.user1.toString() === socket.user.id.toString()
//           ? friendship.user2.toString()
//           : friendship.user1.toString();
//       });

//       console.log(`[Socket] 👥 User ${socket.user.userId} has ${friendIds.length} friends`);
      
//       friendIds.forEach((friendId) => {
//         const friendSocketId = onlineUsers.get(friendId);
//         if (friendSocketId) {
//           io.to(friendSocketId).emit('userStatus', {
//             userId: socket.user.id.toString(),
//             isOnline: true,
//           });
//           console.log(`[Socket] 📡 Emitting 'userStatus' for ${socket.user.userId} (online) to friend ${friendId}`);
//         }
//       });
//     } catch (error) {
//       console.error(`[Socket] ❌ Error on user connection (${socket.user.userId}):`, error);
//     }

//     // ===============================
//     // SEND MESSAGE EVENT HANDLER
//     // ===============================
//     socket.on('sendMessage', async (data) => {
//       console.log(`\n[Socket] ==========================================`);
//       console.log(`[Socket] 📨 Received 'sendMessage' event from ${socket.user.userId}`);
//       console.log(`[Socket] 📨 Event data:`, JSON.stringify(data, null, 2));
//       console.log(`[Socket] 📨 Sender ID: ${socket.user.id}`);
//       console.log(`[Socket] 📨 Recipient ID: ${data.recipientId}`);
//       console.log(`[Socket] 📨 Recipient socket ID: ${onlineUsers.get(data.recipientId)}`);
//       console.log(`[Socket] ==========================================\n`);

//       const { recipientId, text, attachment } = data;
//       const senderId = socket.user.id;
//       const senderName = socket.user.name || 'Unknown User';
//       const senderPhotoURL = socket.user.photoURL;

//       try {
//         // Find or create conversation
//         let conversation = await Conversation.findOne({
//           participants: { $all: [senderId, recipientId] },
//         });

//         if (!conversation) {
//           conversation = new Conversation({
//             participants: [senderId, recipientId],
//           });
//           await conversation.save();
//           console.log(`[DB] ✅ New conversation ${conversation._id} created between ${senderId} and ${recipientId}`);
//         } else {
//           console.log(`[DB] 📁 Found existing conversation: ${conversation._id}`);
//         }

//         // Create new message
//         const newMessage = new Message({
//           conversationId: conversation._id,
//           sender: senderId,
//           recipient: recipientId,
//           text: text,
//           attachment: attachment,
//           status: 'sent',
//         });

//         await newMessage.save();
//         console.log(`[DB] ✅ Message ${newMessage._id} stored. Status: ${newMessage.status}`);
//         console.log(`[DB] 📝 Message content: "${text || (attachment ? attachment.type : 'No content')}"`);

//         // Prepare message object for clients
//         const fullMessage = {
//           ...newMessage.toObject(),
//           sender: {
//             _id: senderId,
//             name: senderName,
//             avatar: senderPhotoURL,
//           },
//           conversationId: conversation._id.toString()
//         };

//         // Emit to recipient if online
//         const recipientSocketId = onlineUsers.get(recipientId);
//         if (recipientSocketId) {
//           console.log(`[Socket] 📡 Recipient ${recipientId} is online (socket ID: ${recipientSocketId})`);
          
//           // Update message status to delivered
//           await Message.findByIdAndUpdate(newMessage._id, { 
//             status: 'delivered', 
//             deliveredAt: new Date() 
//           });
//           fullMessage.status = 'delivered';
//           fullMessage.deliveredAt = new Date();
          
//           // Emit to recipient
//           io.to(recipientSocketId).emit('receiveMessage', fullMessage);
//           console.log(`[Socket] 📡 Emitting 'receiveMessage' to online recipient ${recipientId} for message ${newMessage._id}`);
          
//           // Emit delivery status to sender
//           socket.emit('messageStatusUpdate', { 
//             _id: newMessage._id.toString(), 
//             status: 'delivered', 
//             deliveredAt: fullMessage.deliveredAt 
//           });
//           console.log(`[Socket] 📡 Emitting 'messageStatusUpdate' (delivered) to sender ${senderId} for message ${newMessage._id}`);
//         } else {
//           console.log(`[Socket] ⚠️ Recipient ${recipientId} is offline, message will be delivered via FCM`);
//         }

//         // Always emit to sender for confirmation
//         socket.emit('receiveMessage', fullMessage);
//         console.log(`[Socket] 📡 Emitting 'receiveMessage' to sender ${senderId} for message ${newMessage._id}`);

//         // Send FCM notification to recipient
//         const recipientUser = await User.findById(recipientId);
//         if (recipientUser) {
//           console.log(`[FCM] 🚀 Sending notification to recipient ${recipientId}...`);
//           await fcmService.sendNewMessageNotification(
//             recipientId,
//             socket.user, // Sender object
//             newMessage,
//             conversation._id
//           );
//           console.log(`[FCM] ✅ Notification triggered for recipient ${recipientId} for message ${newMessage._id}`);
//         } else {
//           console.warn(`[FCM] ⚠️ Recipient user ${recipientId} not found, cannot send FCM notification.`);
//         }

//       } catch (error) {
//         console.error(`[Socket] ❌ Error sending message for ${senderId}:`, error);
//         console.error(error.stack);
//       }
//     });

//     // ===============================
//     // MESSAGE DELIVERED EVENT HANDLER
//     // ===============================
//     socket.on('messageDelivered', async ({ messageId }) => {
//       console.log(`\n[Socket] ==========================================`);
//       console.log(`[Socket] ✅ Received 'messageDelivered' for message ${messageId} from ${socket.user.userId}`);
      
//       try {
//         const message = await Message.findByIdAndUpdate(
//           messageId,
//           { status: 'delivered', deliveredAt: new Date() },
//           { new: true }
//         );

//         if (message) {
//           console.log(`[DB] ✅ Message ${messageId} status updated to 'delivered'`);
//           const senderSocketId = onlineUsers.get(message.sender.toString());
//           if (senderSocketId) {
//             io.to(senderSocketId).emit('messageStatusUpdate', {
//               _id: message._id.toString(),
//               status: message.status,
//               deliveredAt: message.deliveredAt,
//             });
//             console.log(`[Socket] 📡 Emitting 'messageStatusUpdate' (delivered) to sender ${message.sender} for message ${messageId}`);
//           }
//         } else {
//           console.warn(`[DB] ⚠️ Message ${messageId} not found for status update.`);
//         }
//       } catch (error) {
//         console.error(`[Socket] ❌ Error updating message delivered status for ${messageId}:`, error);
//       }
//       console.log(`[Socket] ==========================================\n`);
//     });

//     // ===============================
//     // MESSAGE READ EVENT HANDLER
//     // ===============================
//     socket.on('messageRead', async ({ messageId }) => {
//       console.log(`\n[Socket] ==========================================`);
//       console.log(`[Socket] 👁️ Received 'messageRead' for message ${messageId} from ${socket.user.userId}`);
      
//       try {
//         const message = await Message.findByIdAndUpdate(
//           messageId,
//           { status: 'read', readAt: new Date() },
//           { new: true }
//         );

//         if (message) {
//           console.log(`[DB] ✅ Message ${messageId} status updated to 'read'`);
//           const senderSocketId = onlineUsers.get(message.sender.toString());
//           if (senderSocketId) {
//             io.to(senderSocketId).emit('messageStatusUpdate', {
//               _id: message._id.toString(),
//               status: message.status,
//               readAt: message.readAt,
//             });
//             console.log(`[Socket] 📡 Emitting 'messageStatusUpdate' (read) to sender ${message.sender} for message ${messageId}`);
//           }
//         } else {
//           console.warn(`[DB] ⚠️ Message ${messageId} not found for status update.`);
//         }
//       } catch (error) {
//         console.error(`[Socket] ❌ Error updating message read status for ${messageId}:`, error);
//       }
//       console.log(`[Socket] ==========================================\n`);
//     });

//     // ===============================
//     // TYPING STATUS EVENT HANDLERS
//     // ===============================
//     socket.on('typing', (data) => {
//       const { recipientId } = data;
//       console.log(`[Socket] ✍️ User ${socket.user.userId} is typing for ${recipientId}`);
      
//       const recipientSocketId = onlineUsers.get(recipientId);
//       if (recipientSocketId) {
//         io.to(recipientSocketId).emit('typingStatus', {
//           senderId: socket.user.id.toString(),
//           isTyping: true,
//         });
//       }
//     });

//     socket.on('stopTyping', (data) => {
//       const { recipientId } = data;
//       console.log(`[Socket] ✍️ User ${socket.user.userId} stopped typing for ${recipientId}`);
      
//       const recipientSocketId = onlineUsers.get(recipientId);
//       if (recipientSocketId) {
//         io.to(recipientSocketId).emit('typingStatus', {
//           senderId: socket.user.id.toString(),
//           isTyping: false,
//         });
//       }
//     });

//     // ===============================
//     // DISCONNECT EVENT HANDLER
//     // ===============================
//     socket.on('disconnect', async (reason) => {
//       console.log(`\n[Socket] ==========================================`);
//       console.log(`[Socket] 🔴 User disconnected: ${socket.user.userId} (${socket.user.id})`);
//       console.log(`[Socket] 📍 Socket ID: ${socket.id}`);
//       console.log(`[Socket] 📍 Reason: ${reason}`);
      
//       // Remove user from online users map
//       onlineUsers.delete(socket.user.id.toString());
//       console.log(`[Socket] 👥 Total online users after disconnect: ${onlineUsers.size}`);

//       try {
//         const userData = await UserData.findOne({ userId: socket.user.id });
//         if (userData) {
//           userData.isOnline = false;
//           userData.lastActive = new Date();
//           // Ensure location object is valid before saving
//           if (!userData.location || !userData.location.type || !userData.location.coordinates || userData.location.coordinates.length !== 2) {
//             userData.location = {
//               type: 'Point',
//               coordinates: [0, 0]
//             };
//           }
//           await userData.save();
//           console.log(`[DB] ✅ UserData for ${socket.user.userId} updated: isOnline = false, lastActive = ${userData.lastActive}`);
//         } else {
//            console.warn(`[DB] ⚠️ UserData not found for disconnected user ${socket.user.userId}`);
//         }

//         // Broadcast offline status to friends
//         const friendships = await Friendship.find({
//           $or: [{ user1: socket.user.id, status: 'accepted' }, { user2: socket.user.id, status: 'accepted' }],
//         });

//         const friendIds = friendships.map((friendship) => {
//           return friendship.user1.toString() === socket.user.id.toString()
//             ? friendship.user2.toString()
//             : friendship.user1.toString();
//         });

//         console.log(`[Socket] 📡 Broadcasting offline status to ${friendIds.length} friends`);
        
//         friendIds.forEach((friendId) => {
//           const friendSocketId = onlineUsers.get(friendId);
//           if (friendSocketId) {
//             io.to(friendSocketId).emit('userStatus', {
//               userId: socket.user.id.toString(),
//               isOnline: false,
//               lastSeen: userData ? userData.lastActive : null,
//             });
//             console.log(`[Socket] 📡 Emitting 'userStatus' for ${socket.user.userId} (offline) to friend ${friendId}`);
//           }
//         });
//       } catch (error) {
//         console.error(`[Socket] ❌ Error on user disconnect (${socket.user.userId}):`, error);
//       }
//       console.log(`[Socket] ==========================================\n`);
//     });

//     // ===============================
//     // PING/PONG FOR CONNECTION TESTING
//     // ===============================
//     socket.on('ping', (data) => {
//       console.log(`[Socket] 🏓 Received ping from ${socket.user.userId}:`, data);
//       socket.emit('pong', { 
//         message: 'Pong!', 
//         timestamp: new Date().toISOString(),
//         userId: socket.user.userId,
//         socketId: socket.id
//       });
//     });

//     // ===============================
//     // TEST EVENT HANDLER
//     // ===============================
//     socket.on('test', (data) => {
//       console.log(`[Socket] 🧪 Received test event from ${socket.user.userId}:`, data);
//       socket.emit('test_response', {
//         success: true,
//         message: 'Test successful!',
//         data: data,
//         timestamp: new Date().toISOString(),
//         userId: socket.user.userId
//       });
//     });
//   });

//   // Log server startup
//   console.log(`\n[Socket] 🚀 Socket.IO server is ready to accept connections`);
//   console.log(`[Socket] 🌐 Server URL: http://localhost:${server.address().port || 5000}`);
//   console.log(`[Socket] 📡 Transport protocols: websocket, polling\n`);
// };

// module.exports = { initSocket };




const socketio = require('socket.io');
const jwt = require('jsonwebtoken');
const UserData = require('../models/UserData');
const User = require('../models/userModel');
const Message = require('../models/messageModel');
const Conversation = require('../models/conversationModel');
const Friendship = require('../models/Friendship');
const fcmService = require('./fcmService'); // Added fcmService import

const onlineUsers = new Map();

const initSocket = (server) => {
  const io = socketio(server, {
    cors: {
      origin: '*',
    },
  });

  io.use(async (socket, next) => {
    const token = socket.handshake.query.token;
    if (!token) {
      console.log('[Socket] Authentication error: No token provided');
      return next(new Error('Authentication error: No token provided'));
    }
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.user = await User.findById(decoded.id);
      if (!socket.user) {
        console.log('[Socket] Authentication error: User not found for token');
        return next(new Error('Authentication error: User not found'));
      }
      next();
    } catch (error) {
      console.error('[Socket] JWT verification error:', error.message);
      return next(new Error('Authentication error: Invalid token'));
    }
  });

  io.on('connection', async (socket) => {
    console.log(`[Socket] User connected: ${socket.user.userId} (${socket.user.id}) with socket ID ${socket.id}`);
    onlineUsers.set(socket.user.id.toString(), socket.id);

    try {
      let userData = await UserData.findOne({ userId: socket.user.id });
      if (userData) {
        userData.isOnline = true;
        // Ensure location object is valid
        if (!userData.location || !userData.location.type || !userData.location.coordinates || userData.location.coordinates.length !== 2) {
          userData.location = {
            type: 'Point',
            coordinates: [0, 0]
          };
        }
        await userData.save();
        console.log(`[DB] UserData for ${socket.user.userId} updated: isOnline = true`);
      } else {
        // Create new UserData if it doesn't exist
        userData = new UserData({ 
          userId: socket.user.id, 
          isOnline: true,
          location: {
            type: 'Point',
            coordinates: [0, 0]
          }
        });
        await userData.save();
        console.log(`[DB] New UserData created for ${socket.user.userId} with isOnline = true`);
      }

      // Broadcast online status to friends
      const friendships = await Friendship.find({
        $or: [{ user1: socket.user.id, status: 'accepted' }, { user2: socket.user.id, status: 'accepted' }],
      });

      const friendIds = friendships.map((friendship) => {
        return friendship.user1.toString() === socket.user.id.toString()
          ? friendship.user2.toString()
          : friendship.user1.toString();
      });

      friendIds.forEach((friendId) => {
        const friendSocketId = onlineUsers.get(friendId);
        if (friendSocketId) {
          io.to(friendSocketId).emit('userStatus', {
            userId: socket.user.id.toString(),
            isOnline: true,
          });
          console.log(`[Socket] Emitting 'userStatus' for ${socket.user.userId} (online) to friend ${friendId}`);
        }
      });
    } catch (error) {
      console.error(`[Socket] Error on user connection (${socket.user.userId}):`, error);
    }


    // In your backend socket.js, modify the message sending logic:
socket.on('sendMessage', async (data) => {
  const { recipientId, text, attachment } = data;
  const senderId = socket.user.id;
  const senderName = socket.user.name || 'Unknown User';
  const senderPhotoURL = socket.user.photoURL;

  console.log(`[Socket] Message received from ${senderId} for ${recipientId}. Content: ${text || attachment?.type}`);

  try {
    let conversation = await Conversation.findOne({
      participants: { $all: [senderId, recipientId] },
    });

    if (!conversation) {
      conversation = new Conversation({
        participants: [senderId, recipientId],
      });
      await conversation.save();
      console.log(`[DB] New conversation created`);
    }

    const newMessage = new Message({
      conversationId: conversation._id,
      sender: senderId,
      recipient: recipientId,
      text: text,
      attachment: attachment,
      status: 'sent',
    });

    await newMessage.save();
    console.log(`[DB] Message ${newMessage._id} stored.`);

    // Prepare message object
    const fullMessage = {
      ...newMessage.toObject(),
      sender: {
        _id: senderId,
        name: senderName,
        avatar: senderPhotoURL,
      },
      conversationId: conversation._id.toString()
    };

    // ONLY EMIT TO RECIPIENT if they're online
    const recipientSocketId = onlineUsers.get(recipientId);
    if (recipientSocketId) {
      // Update status to delivered
      fullMessage.status = 'delivered';
      await Message.findByIdAndUpdate(newMessage._id, { 
        status: 'delivered', 
        deliveredAt: new Date() 
      });
      
      // Emit to recipient
      io.to(recipientSocketId).emit('receiveMessage', fullMessage);
      console.log(`[Socket] Emitting to recipient ${recipientId}`);
      
      // Notify sender that message was delivered
      socket.emit('messageStatusUpdate', { 
        _id: newMessage._id, 
        status: 'delivered', 
        deliveredAt: fullMessage.deliveredAt 
      });
    } else {
      // If recipient is offline, emit status update to sender
      socket.emit('messageStatusUpdate', { 
        _id: newMessage._id, 
        status: 'sent' 
      });
    }

    // DO NOT emit receiveMessage to sender here - let frontend handle optimistic update
    // The frontend already has the optimistic message
    
    // Send FCM notification
    const recipientUser = await User.findById(recipientId);
    if (recipientUser) {
      fcmService.sendNewMessageNotification(
        recipientId,
        socket.user,
        newMessage,
        conversation._id
      );
    }
    
  } catch (error) {
    console.error(`[Socket] Error sending message:`, error);
    // Notify sender of failure
    socket.emit('messageError', { 
      error: 'Failed to send message',
      tempId: data.tempId // Add tempId to identify optimistic message
    });
  }
});

    // Handle message delivered status
    socket.on('messageDelivered', async ({ messageId }) => {
      console.log(`[Socket] Received 'messageDelivered' for message ${messageId} from ${socket.user.userId}`);
      try {
        const message = await Message.findByIdAndUpdate(
          messageId,
          { status: 'delivered', deliveredAt: new Date() },
          { new: true }
        );

        if (message) {
          console.log(`[DB] Message ${messageId} status updated to 'delivered'`);
          const senderSocketId = onlineUsers.get(message.sender.toString());
          if (senderSocketId) {
            io.to(senderSocketId).emit('messageStatusUpdate', {
              _id: message._id.toString(),
              status: message.status,
              deliveredAt: message.deliveredAt,
            });
            console.log(`[Socket] Emitting 'messageStatusUpdate' (delivered) to sender ${message.sender} for message ${messageId}`);
          }
        } else {
          console.warn(`[DB] Message ${messageId} not found for status update.`);
        }
      } catch (error) {
        console.error(`[Socket] Error updating message delivered status for ${messageId}:`, error);
      }
    });

    // Handle message read status
    socket.on('messageRead', async ({ messageId }) => {
      console.log(`[Socket] Received 'messageRead' for message ${messageId} from ${socket.user.userId}`);
      try {
        const message = await Message.findByIdAndUpdate(
          messageId,
          { status: 'read', readAt: new Date() },
          { new: true }
        );

        if (message) {
          console.log(`[DB] Message ${messageId} status updated to 'read'`);
          const senderSocketId = onlineUsers.get(message.sender.toString());
          if (senderSocketId) {
            io.to(senderSocketId).emit('messageStatusUpdate', {
              _id: message._id.toString(),
              status: message.status,
              readAt: message.readAt,
            });
            console.log(`[Socket] Emitting 'messageStatusUpdate' (read) to sender ${message.sender} for message ${messageId}`);
          }
        } else {
          console.warn(`[DB] Message ${messageId} not found for status update.`);
        }
      } catch (error) {
        console.error(`[Socket] Error updating message read status for ${messageId}:`, error);
      }
    });

    // Handle typing status
    socket.on('typing', (data) => {
      const { recipientId } = data;
      console.log(`[Socket] User ${socket.user.userId} is typing for ${recipientId}`);
      const recipientSocketId = onlineUsers.get(recipientId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('typingStatus', {
          senderId: socket.user.id.toString(),
          isTyping: true,
        });
      }
    });

    socket.on('stopTyping', (data) => {
      const { recipientId } = data;
      console.log(`[Socket] User ${socket.user.userId} stopped typing for ${recipientId}`);
      const recipientSocketId = onlineUsers.get(recipientId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('typingStatus', {
          senderId: socket.user.id.toString(),
          isTyping: false,
        });
      }
    });

    socket.on('disconnect', async () => {
      console.log(`[Socket] User disconnected: ${socket.user.userId} (${socket.user.id}) with socket ID ${socket.id}`);
      onlineUsers.delete(socket.user.id.toString());

      try {
        const userData = await UserData.findOne({ userId: socket.user.id });
        if (userData) {
          userData.isOnline = false;
          userData.lastActive = new Date();
          // Ensure location object is valid before saving
          if (!userData.location || !userData.location.type || !userData.location.coordinates || userData.location.coordinates.length !== 2) {
            userData.location = {
              type: 'Point',
              coordinates: [0, 0]
            };
          }
          await userData.save();
          console.log(`[DB] UserData for ${socket.user.userId} updated: isOnline = false, lastActive = ${userData.lastActive}`);
        } else {
           console.warn(`[DB] UserData not found for disconnected user ${socket.user.userId}`);
        }

        // Broadcast offline status to friends
        const friendships = await Friendship.find({
          $or: [{ user1: socket.user.id, status: 'accepted' }, { user2: socket.user.id, status: 'accepted' }],
        });

        const friendIds = friendships.map((friendship) => {
          return friendship.user1.toString() === socket.user.id.toString()
            ? friendship.user2.toString()
            : friendship.user1.toString();
        });

        friendIds.forEach((friendId) => {
          const friendSocketId = onlineUsers.get(friendId);
          if (friendSocketId) {
            io.to(friendSocketId).emit('userStatus', {
              userId: socket.user.id.toString(),
              isOnline: false,
              lastSeen: userData ? userData.lastActive : null,
            });
            console.log(`[Socket] Emitting 'userStatus' for ${socket.user.userId} (offline) to friend ${friendId}`);
          }
        });
      } catch (error) {
        console.error(`[Socket] Error on user disconnect (${socket.user.userId}):`, error);
      }
    });
  });
};

module.exports = { initSocket };
