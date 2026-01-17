const UserLocation = require('../models/UserLocation');
const User = require('../models/userModel');
const mongoose = require('mongoose');

// Update user location
// Trigger this from frontend on app open, foreground, or movement > 50m
exports.updateLocation = async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    const userId = req.user._id;

    if (latitude === undefined || longitude === undefined) {
      return res.status(400).json({ success: false, message: 'Latitude and longitude are required' });
    }

    // Upsert location data
    const userLocation = await UserLocation.findOneAndUpdate(
      { userId },
      {
        userId,
        location: {
          type: 'Point',
          coordinates: [parseFloat(longitude), parseFloat(latitude)]
        },
        isOnline: true, // Assume online when sending location updates
        lastSeen: new Date(),
        updatedAt: new Date()
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    res.json({ success: true, message: 'Location updated', data: userLocation });
  } catch (error) {
    console.error('Error updating location:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get nearby users
exports.getNearbyUsers = async (req, res) => {
  try {
    const userId = req.user._id;
    const { radius = 2000, includeSelf } = req.query; // Default 2km
    
    console.log(`[Nearby] Fetching users for: ${userId}`);

    // 1. Get current user's location
    const myLocation = await UserLocation.findOne({ userId });

    if (!myLocation) {
      console.log(`[Nearby] Location not found for user: ${userId}`);
      return res.status(400).json({ 
        success: false, 
        message: 'Your location is not set. Please enable location services.' 
      });
    }

    const coordinates = myLocation.location.coordinates;

    // 2. Determine if user is Premium
    // Adjust this check based on your actual Premium logic
    const isPremium = req.user.role === 'premium' || req.user.isPremium === true;

    // 3. Build Query
    const query = {
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: coordinates
          },
          $maxDistance: parseInt(radius)
        }
      }
    };

    // Exclude self unless explicitly requested for testing
    if (includeSelf !== 'true') {
      query.userId = { $ne: userId };
    }

    // 4. Apply filtering based on subscription
    if (!isPremium) {
      // Normal users: Only see ONLINE users
      query.isOnline = true;
      console.log('[Nearby] User is Normal: Filtering for Online users only');
    }
    // Premium users: See everyone in the collection (TTL handles the 24h limit)

    // 5. Execute Query
    const nearbyUsers = await UserLocation.find(query)
      .populate('userId', 'name profilePicture userId')
      .limit(50);

    console.log(`[Nearby] Found ${nearbyUsers.length} users (before formatting)`);

    // 6. Format response with distance
    const formattedUsers = nearbyUsers.map(u => {
        if (!u.userId) return null; // Handle deleted users
        return {
            _id: u.userId._id,
            userId: u.userId.userId,
            name: u.userId.name,
            profilePicture: u.userId.profilePicture,
            isOnline: u.isOnline,
            lastSeen: u.lastSeen,
            distance: Math.round(calculateDistance(coordinates[1], coordinates[0], u.location.coordinates[1], u.location.coordinates[0]))
        };
    }).filter(Boolean);

    res.json({ success: true, count: formattedUsers.length, users: formattedUsers, isPremium });
  } catch (error) {
    console.error('Error fetching nearby users:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Haversine formula for distance in meters
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371e3; // metres
    const φ1 = lat1 * Math.PI/180;
    const φ2 = lat2 * Math.PI/180;
    const Δφ = (lat2-lat1) * Math.PI/180;
    const Δλ = (lon2-lon1) * Math.PI/180;
    const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) + Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ/2) * Math.sin(Δλ/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}