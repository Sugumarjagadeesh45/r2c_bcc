# User Profile Data & Avatar Handling Notes

## Backend Changes
The backend has been updated to **stop sending default avatar URLs** (e.g., randomuser.me images).

### API Behavior for Avatars
- **If the user HAS a profile picture:** The API returns the URL string (e.g., `https://...`).
- **If the user DOES NOT have a profile picture:** The API returns `null` (or empty string) for fields like `avatar` or `photoURL`.

## Frontend Implementation Requirements

The frontend must handle the `null` avatar value by rendering the user's initials instead of an image.

### Logic Flow
1. Check if the user object has a valid `avatar` or `photoURL`.
2. **If valid:** Render the `<Image>` component with that URI.
3. **If null/undefined:** Render the **Initials View** (a colored circle with the first 2 letters of the name).

### Code Snippet Reference (React Native)

Use the following logic to determine what to render:

```javascript
// Helper functions (assumed to exist)
const userInitials = getUserInitials(item.name);
const avatarColor = getAvatarColor(item.name);
const avatarUrl = item.avatar || item.photoURL; // Handle different API response keys

return (
  <View style={styles.friendItem}>
    <TouchableOpacity onPress={() => handleViewProfile(item)} style={styles.avatarContainer}>
      
      {/* CONDITIONAL RENDERING */}
      {avatarUrl ? (
        // 1. REAL PROFILE IMAGE
        <Image 
          source={{ uri: avatarUrl }} 
          style={styles.avatarImage} 
        />
      ) : (
        // 2. INITIALS FALLBACK
        <View style={[styles.avatarCircle, { backgroundColor: avatarColor }]}>
          <Text style={styles.avatarText}>{userInitials}</Text>
        </View>
      )}
      
    </TouchableOpacity>
  </View>
);
```