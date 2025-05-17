/**
 * Main Server File for Elara Regency - Updated for MongoDB & Profile Page
 */
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const mongoose = require('mongoose');

// Import API routes
const apiRoutes = require("./api/apiRoutes");

// Import all middleware from index file (ensure path is correct)
const {
  helmetConfig,
  corsConfig,
  morganLogger,
  requestLogger, // Assuming this is your custom logger
  compressionConfig,
  isAuthenticated,
  isAdmin,
  redirectAdminToDashboard,
} = require("./middlewares");

// Import Mongoose Models needed directly in server.js
const User = require('./models/User');
const Reservation = require('./models/Reservation'); // Needed for admin dashboard & profile

const app = express();
const PORT = process.env.PORT || 3000;

// --- MongoDB Connection ---
// SECURITY: Use environment variables for MONGO_URI in production
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/elara-regency';

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('MongoDB Connected...');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1); // Exit if DB connection fails
  }
};

connectDB();
// --- End MongoDB Connection ---

// Set EJS view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// --- Global Middleware ---
app.use(corsConfig);
app.use(helmetConfig); // Set security headers
app.use(compressionConfig); // Compress responses
app.use(morganLogger); // Log HTTP requests
app.use(requestLogger); // Your custom logger
app.use(cookieParser()); // Parse cookies
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.static(path.join(__dirname, "public"))); // Serve static files
// --- End Global Middleware ---


// --- API Routes ---
// Mount the API routes - all requests starting with /api will go here
app.use("/api", apiRoutes);
// --- End API Routes ---


// --- Page Routes ---

// Set a local variable for templates to easily check login status
// This middleware runs for all subsequent routes defined AFTER it
app.use((req, res, next) => {
    res.locals.isLoggedIn = !!req.cookies.token;
    // SECURITY NOTE: Do not rely solely on the isAdmin cookie for critical checks.
    // The isAdmin middleware should perform proper verification using req.user if available.
    res.locals.isAdmin = req.cookies.isAdmin === 'true';
    next();
});

// Admin dashboard route (requires admin privileges)
app.get("/admin-dashboard", isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Fetch users (excluding passwords) - using lean() for performance
    const users = await User.find({}, '-password').lean();

    // Fetch all reservations, populate user details, sort by submission date
    const reservations = await Reservation.find({})
                                        .populate('userId', 'name email') // Get name/email from User model
                                        .sort({ submittedAt: -1 })
                                        .lean();

    // Render the admin dashboard template with both datasets
    res.render("admin-dashboard", {
      title: "Admin Dashboard - Elara Regency",
      users: users,
      reservations: reservations,
      // isAdmin and isLoggedIn are available via res.locals
    });
  } catch (error) {
    console.error("Error loading admin dashboard data:", error);
    res.status(500).render('error', {
        title: "Server Error",
        message: "Could not load the admin dashboard data.",
        // isLoggedIn and isAdmin are available via res.locals
    });
  }
});

// User Profile Page Route
// Requires authentication, redirects admins away
app.get('/profile', isAuthenticated, redirectAdminToDashboard, async (req, res) => {
    try {
        // req.user should be populated by the enhanced isAuthenticated middleware
        if (!req.user || !req.user.id) {
            return res.redirect('/login?message=Please login to view your profile.');
        }
        const userId = req.user.id;

        // Fetch user details (excluding password)
        const user = await User.findById(userId, '-password').lean();

        if (!user) {
            res.clearCookie("token");
            res.clearCookie("isAdmin");
            return res.redirect('/login?message=Could not find user profile.');
        }

        // Fetch reservations for this user, sorted by check-in date
        const reservations = await Reservation.find({ userId: userId })
                                              .sort({ checkIn: -1 })
                                              .lean();

        // Render the profile page
        res.render('profile', {
            title: 'My Profile',
            user: user,
            reservations: reservations
            // isLoggedIn is available via res.locals
        });

    } catch (error) {
        console.error("Error fetching profile data:", error);
        res.status(500).render('error', {
             title: "Server Error",
             message: "Could not load your profile information.",
             // isLoggedIn is available via res.locals
        });
    }
});


// Publicly accessible pages (Login, Register)
// Redirect logged-in users away
app.get("/register", (req, res) => {
  if (res.locals.isLoggedIn) {
    return res.redirect(res.locals.isAdmin ? "/admin-dashboard" : "/");
  }
  res.render("register", { title: "Register - Elara Regency" });
});

app.get("/login", (req, res) => {
  if (res.locals.isLoggedIn) {
    return res.redirect(res.locals.isAdmin ? "/admin-dashboard" : "/");
  }
  res.render("login", { title: "Login - Elara Regency" });
});

// Logout route
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.clearCookie("isAdmin");
  res.redirect("/");
});


// Regular site pages - Apply admin redirection middleware
app.get("/", redirectAdminToDashboard, (req, res) => {
  res.render("home", { title: "Elara Regency - Luxury Hotel" });
});

const regularPages = ["/rooms", "/locations", "/contact", "/about", "/blog"];
regularPages.forEach((pagePath) => {
  app.get(pagePath, redirectAdminToDashboard, (req, res) => {
    const pageName = pagePath.substring(1);
    const title = pageName.charAt(0).toUpperCase() + pageName.slice(1);
    res.render(pageName, { title: `${title} - Elara Regency` });
  });
});

// Location detail pages - Apply admin redirection middleware
app.get("/locations/:location", redirectAdminToDashboard, (req, res, next) => { // Added next
  try {
      const location = req.params.location;
      // Basic input validation/sanitization
      const safeLocation = location.replace(/[^a-zA-Z0-9-_]/g, '');
      if (!safeLocation) {
          // Handle empty or invalid location parameter, maybe redirect or show 404
          return next(); // Pass to 404 handler
      }
      const title = safeLocation.charAt(0).toUpperCase() + safeLocation.slice(1);
      // Check if view exists or handle dynamically
      res.render("location-detail", { // Assumes location-detail.ejs exists
        title: `${title} - Elara Regency`,
        location: safeLocation,
      });
  } catch (error) {
      // If rendering fails or other error occurs
      next(error); // Pass error to global error handler
  }
});

// Authenticated pages (example: Reservation)
// Apply isAuthenticated and redirectAdminToDashboard middleware
app.get("/reservation", isAuthenticated, redirectAdminToDashboard, (req, res) => {
  res.render("reservation", { title: "Make a Reservation - Elara Regency" });
});

// --- End Page Routes ---


// --- 404 Handler for Pages (After all other routes) ---
// This catches requests that didn't match any defined page or API route
app.use((req, res) => {
  res.status(404).render('404', { title: "Page Not Found" });
});
// --- End 404 Handler ---


// --- Global Error Handler (Last middleware) ---
// Catches errors passed via next(error)
app.use((err, req, res, next) => {
    console.error("Global Error Handler:", err.stack);
    res.status(err.status || 500).render('error', {
        title: "Server Error",
        // Provide more details only in development for security
        message: process.env.NODE_ENV === 'production' ? "An unexpected error occurred." : err.message,
        // isLoggedIn and isAdmin are available via res.locals
    });
});
// --- End Global Error Handler ---


// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
