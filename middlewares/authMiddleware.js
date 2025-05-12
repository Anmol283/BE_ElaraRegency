// middlewares/authMiddleware.js
/**
 * Authentication and authorization middleware for Elara Regency
 */
const User = require('../models/User'); // Import User model if needed for validation

// Check if user is authenticated
const isAuthenticated = async (req, res, next) => { // Make it async if fetching user data
  const token = req.cookies.token;
  if (!token) {
    return res.redirect("/login?message=Please login to continue"); // Redirect with a message
  }

  try {
    // --- INSECURE EXAMPLE - REPLACE WITH JWT/SESSION VALIDATION ---
    // Extract ID from cookie name 'user-token-<ID>'
    const parts = token.split('user-token-');
    if (parts.length !== 2 || !parts[1]) {
        throw new Error('Invalid token format');
    }
    const userId = parts[1];

    // Optional but recommended: Verify the user ID actually exists in the DB
    const user = await User.findById(userId, '_id isAdmin'); // Fetch only needed fields
    if (!user) {
         // Clear invalid cookies and redirect
         res.clearCookie("token");
         res.clearCookie("isAdmin");
         return res.redirect("/login?message=Invalid session, please login again");
    }
    // --- END OF INSECURE EXAMPLE ---

    // Attach user information (at least ID) to the request object
    // In a real JWT/Session setup, you'd get this info securely from the decoded token/session data
    req.user = {
        id: user._id.toString(), // Attach user's MongoDB ID
        isAdmin: user.isAdmin
    };

    next(); // User is authenticated, proceed to the next middleware/route handler

  } catch (error) {
    console.error("Authentication error:", error.message);
    // Clear cookies if authentication fails
    res.clearCookie("token");
    res.clearCookie("isAdmin");
    return res.redirect("/login?message=Authentication failed, please login again");
  }
};

// Check if user is admin (Uses isAuthenticated first implicitly if chained)
const isAdmin = (req, res, next) => {
  // This middleware should run *after* isAuthenticated successfully attaches req.user
  if (!req.user || !req.user.isAdmin) {
     // If not admin, redirect or send forbidden error
     // Redirecting to home might be better UX than just login
     return res.redirect('/?message=Admin access required');
     // Or res.status(403).send('Forbidden: Admin access required');
  }
  next(); // User is an admin
};

// Redirect admin users away from regular pages to their dashboard
const redirectAdminToDashboard = (req, res, next) => {
  // Check cookie directly or use req.user if isAuthenticated runs before this
  const isAdminUser = req.cookies.isAdmin === "true"; // Or check req.user.isAdmin if available
  // Prevent admins from accessing non-admin pages unnecessarily
  if (isAdminUser && req.path !== "/admin-dashboard" && !req.path.startsWith('/api/')) {
      // Allow access to logout
      if (req.path === '/logout') {
          return next();
      }
     return res.redirect("/admin-dashboard");
  }
  next();
};

module.exports = {
  isAuthenticated,
  isAdmin,
  redirectAdminToDashboard,
};