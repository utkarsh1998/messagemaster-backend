import mongoose from 'mongoose';

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    // Set an expiry for the OTP, e.g., 10 minutes
    expires: 600, 
  },
});

const Otp = mongoose.model('Otp', otpSchema);

export default Otp;
