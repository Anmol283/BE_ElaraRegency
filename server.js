/**
 * Main Server File for Elara Regency - Connected to MongoDB Atlas
 */
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
require("dotenv").config(); // ✅ Load .env variables early

// Import API routes
const apiRoutes = require("./api/apiRoutes");

// Import middlewares
const {
  helmetConfig,
  corsConfig,
  morganLogger,
  requestLogger,
  compressionConfig,
  isAuthenticated,
  isAdmin,
  redirectAdminToDashboard,
} = require("./middlewares");

// Import models
const User = require("./models/User");
const Reservation = require("./models/Reservation");

const app = express();
const PORT = process.env.PORT || 3000;

// --- ✅ MongoDB Atlas Connection ---
const MONGO_URI = process.env.MONGO_URI;

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB Atlas connected");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  }
};
connectDB();
// --- End MongoDB Connection ---

// View engine setup
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Global Middleware
app.use(corsConfig);
app.use(helmetConfig);
app.use(compressionConfig);
app.use(morganLogger);
app.use(requestLogger);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// API routes
app.use("/api", apiRoutes);

// Middleware to set template flags
app.use((req, res, next) => {
  res.locals.isLoggedIn = !!req.cookies.token;
  res.locals.isAdmin = req.cookies.isAdmin === "true";
  next();
});

// --- Page Routes ---

// Admin dashboard
app.get("/admin-dashboard", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, "-password").lean();
    const reservations = await Reservation.find({})
      .populate("userId", "name email")
      .sort({ submittedAt: -1 })
      .lean();
    res.render("admin-dashboard", {
      title: "Admin Dashboard - Elara Regency",
      users,
      reservations,
    });
  } catch (error) {
    console.error("Error loading admin dashboard:", error);
    res.status(500).render("error", {
      title: "Server Error",
      message: "Could not load the admin dashboard data.",
    });
  }
});

// Profile page
app.get("/profile", isAuthenticated, redirectAdminToDashboard, async (req, res) => {
  try {
    if (!req.user || !req.user.id) {
      return res.redirect("/login?message=Please login to view your profile.");
    }

    const user = await User.findById(req.user.id, "-password").lean();
    if (!user) {
      res.clearCookie("token");
      res.clearCookie("isAdmin");
      return res.redirect("/login?message=Could not find user profile.");
    }

    const reservations = await Reservation.find({ userId: user._id })
      .sort({ checkIn: -1 })
      .lean();

    res.render("profile", {
      title: "My Profile",
      user,
      reservations,
    });
  } catch (error) {
    console.error("Error fetching profile data:", error);
    res.status(500).render("error", {
      title: "Server Error",
      message: "Could not load your profile information.",
    });
  }
});

// Login/Register
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

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.clearCookie("isAdmin");
  res.redirect("/");
});

// Public pages
app.get("/", redirectAdminToDashboard, (req, res) => {
  res.render("home", { title: "Elara Regency - Luxury Hotel" });
});

["/rooms", "/locations", "/contact", "/about", "/blog"].forEach((path) => {
  app.get(path, redirectAdminToDashboard, (req, res) => {
    const title = path.substring(1).replace(/^\w/, (c) => c.toUpperCase());
    res.render(path.substring(1), { title: `${title} - Elara Regency` });
  });
});

app.get("/locations/:location", redirectAdminToDashboard, (req, res, next) => {
  try {
    const location = req.params.location.replace(/[^a-zA-Z0-9-_]/g, "");
    if (!location) return next();
    const title = location.charAt(0).toUpperCase() + location.slice(1);
    res.render("location-detail", {
      title: `${title} - Elara Regency`,
      location,
    });
  } catch (error) {
    next(error);
  }
});

app.get("/reservation", isAuthenticated, redirectAdminToDashboard, (req, res) => {
  res.render("reservation", { title: "Make a Reservation - Elara Regency" });
});

// 404 Page
app.use((req, res) => {
  res.status(404).render("404", { title: "Page Not Found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global Error Handler:", err.stack);
  res.status(err.status || 500).render("error", {
    title: "Server Error",
    message: process.env.NODE_ENV === "production" ? "An unexpected error occurred." : err.message,
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
