/**
 * API Routes for Elara Regency - Updated for MongoDB & User Linking
 */
const express = require("express");
const router = express.Router();

// Import Mongoose Models
const User = require('../models/User');
const Reservation = require('../models/Reservation');
const ContactMessage = require('../models/ContactMessage');

// Import necessary middleware (ensure path is correct)
const { isAuthenticated, isAdmin } = require('../middlewares');

// Register a new user
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Basic validation
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters long" });
    }

    // Check if user already exists in MongoDB
    const userExists = await User.findOne({ email: email.toLowerCase() });

    if (userExists) {
      return res.status(400).json({ success: false, message: "User already exists with this email" });
    }

    // Create new user instance (password will be hashed by pre-save middleware in User.js)
    const newUser = new User({
      name,
      email: email.toLowerCase(),
      password,
      isAdmin: false // Default for new registrations
    });

    // Save the new user to the database
    const savedUser = await newUser.save();

    // Set cookies upon successful registration
    // SECURITY WARNING: Replace this basic cookie with JWT or secure sessions
    res.cookie("token", "user-token-" + savedUser._id, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    res.cookie("isAdmin", savedUser.isAdmin.toString(), { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });

    // Return success response
    return res.status(201).json({ success: true, message: "User registered successfully" });

  } catch (error) {
    console.error("Registration error:", error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: error.message });
    }
    return res.status(500).json({ success: false, message: "Server error during registration" });
  }
});

// Login user
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    // Find user by email in MongoDB
    const user = await User.findOne({ email: email.toLowerCase() });

    // Check if user exists and if the entered password matches the hashed password
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    // Set cookies upon successful login
    // SECURITY WARNING: Replace this basic cookie with JWT or secure sessions
    res.cookie("token", "user-token-" + user._id, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    res.cookie("isAdmin", user.isAdmin.toString(), { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });

    // Return success response with role and redirect URL
    return res.status(200).json({
      success: true,
      message: "Login successful",
      isAdmin: user.isAdmin,
      redirectUrl: user.isAdmin ? "/admin-dashboard" : "/",
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ success: false, message: "Server error during login" });
  }
});

// Get all users (admin only)
// Apply isAdmin middleware (which should implicitly use isAuthenticated first if chained correctly)
router.get("/users", isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Check if user is admin (already done by middleware, but double check doesn't hurt)
     if (!req.user || !req.user.isAdmin) {
       return res.status(403).json({ success: false, message: "Forbidden: Admin access required" });
     }
    // Fetch users from MongoDB, excluding the password field for security
    const users = await User.find({}, '-password').lean();
    return res.status(200).json({ success: true, users: users });

  } catch (error) {
    console.error("Get users error:", error);
    return res.status(500).json({ success: false, message: "Server error fetching users" });
  }
});

// Submit reservation
// Apply isAuthenticated middleware to ensure user is logged in
router.post("/reservation", isAuthenticated, async (req, res) => {
  try {
    const { checkIn, checkOut, roomType, guests, specialRequests } = req.body;

    // Basic validation
    if (!checkIn || !checkOut || !roomType || !guests) {
      return res.status(400).json({ success: false, message: "Required reservation fields missing: Check-in, Check-out, Room Type, Guests" });
    }
    // Check if user ID is available from middleware (populated by our example isAuthenticated)
    if (!req.user || !req.user.id) {
      return res.status(401).json({ success: false, message: "Authentication error, cannot process reservation." });
    }

    // Create a new reservation instance, linking it to the user
    const newReservation = new Reservation({
      checkIn: new Date(checkIn),
      checkOut: new Date(checkOut),
      roomType,
      guests: parseInt(guests, 10),
      specialRequests: specialRequests || 'None',
      userId: req.user.id // Get the user ID from the request object
    });

    // Save the reservation to the database
    const savedReservation = await newReservation.save();

    // Return success response with the created reservation details
    return res.status(201).json({
      success: true,
      message: "Reservation submitted successfully",
      reservation: savedReservation,
    });
  } catch (error) {
    console.error("Reservation error:", error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: error.message });
    }
    return res.status(500).json({ success: false, message: "Server error submitting reservation" });
  }
});

// Submit contact form
router.post("/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Basic validation
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ success: false, message: "All contact fields are required: Name, Email, Subject, Message" });
    }

    // Create a new contact message instance
    const newContactMessage = new ContactMessage({
      name,
      email,
      subject,
      message
    });

    // Save the contact message to the database
    await newContactMessage.save();

    // Return success response
    return res.status(200).json({
      success: true,
      message: "Message sent successfully. We will get back to you soon.",
    });
  } catch (error) {
    console.error("Contact form error:", error);
    if (error.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: error.message });
    }
    return res.status(500).json({ success: false, message: "Server error sending message" });
  }
});

// Catch-all for 404 errors within the API routes (/api/*)
router.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `API endpoint not found: ${req.method} ${req.originalUrl}`,
  });
});

module.exports = router;