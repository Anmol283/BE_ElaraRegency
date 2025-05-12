// models/Reservation.js
const mongoose = require('mongoose');

const reservationSchema = new mongoose.Schema({
  // --- Add this field ---
  userId: {
    type: mongoose.Schema.Types.ObjectId, // Reference to the User's _id
    ref: 'User', // Links to the 'User' model
    required: true, // Make it mandatory
    index: true // Add an index for faster lookups by user
  },
  // --- End of added field ---
  checkIn: {
    type: Date,
    required: true
  },
  checkOut: {
    type: Date,
    required: true
  },
  roomType: {
    type: String,
    required: true,
    trim: true
  },
  guests: {
    type: Number,
    required: true,
    min: 1
  },
  specialRequests: {
    type: String,
    trim: true,
    default: 'None'
  },
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Reservation', reservationSchema);