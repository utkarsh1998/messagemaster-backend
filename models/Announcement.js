import mongoose from "mongoose";

const announcementSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
    },
    message: {
      type: String,
      required: true,
    },
    // ✅ NEW: Field to control who can see the announcement
    visibility: {
      type: {
        type: String,
        enum: ['all', 'reseller', 'specific'], // 'all', 'reseller', or 'specific' users
        required: true,
        default: 'all',
      },
      // If type is 'reseller' or 'specific', this will hold their emails
      targets: {
        type: [String],
        default: [],
      },
    },
    link: {
      type: String, // Optional URL
    },
    image: {
      type: String, // Optional path to an uploaded image
    },
    expiryDate: {
      type: Date,
    },
    seenBy: {
      type: [String],
      default: [],
    },
    createdBy: {
      type: String, // Admin's email
      required: true,
    },
  },
  { timestamps: true }
);

const Announcement = mongoose.model("Announcement", announcementSchema);

export default Announcement;
