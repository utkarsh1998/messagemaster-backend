import mongoose from "mongoose";

const notificationSchema = new mongoose.Schema(
  {
    // The user who should receive this notification
    userEmail: {
      type: String,
      required: true,
    },
    // The main message of the notification
    message: {
      type: String,
      required: true,
    },
    // A link to the relevant page (e.g., a specific ticket or campaign)
    link: {
      type: String,
    },
    // The status of the notification
    isRead: {
      type: Boolean,
      default: false,
    },
    // The type of event that triggered the notification
    eventType: {
        type: String,
        enum: [
            'NewUserCreated',
            'NewCampaign',
            'CampaignStatusUpdate',
            'NewTicket',
            'TicketReply',
            'TicketStatusUpdate',
            'NewAnnouncement'
        ],
        required: true,
    },
  },
  { timestamps: true }
);

const Notification = mongoose.model("Notification", notificationSchema);

export default Notification;
