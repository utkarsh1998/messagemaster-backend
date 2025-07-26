import mongoose from "mongoose";

const replySchema = new mongoose.Schema(
  {
    userEmail: { type: String, required: true },
    message: { type: String, required: true },
  },
  { timestamps: true }
);

const ticketSchema = new mongoose.Schema(
  {
    userEmail: { type: String, required: true },
    subject: { type: String, required: true },
    description: { type: String, required: true },
    attachments: { type: [String], default: [] },
    status: {
      type: String,
      enum: ["Open", "In Progress", "Resolved", "Closed", "Escalated"],
      default: "Open",
    },
    replies: [replySchema],
    
    // Fields to link tickets to other data
    issueType: {
        type: String,
        enum: ["Campaign", "User", "Credits/Debits", "Other"],
        required: true
    },
    relatedCampaign: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    relatedUser: { type: String },
    relatedTransaction: { type: mongoose.Schema.Types.ObjectId, ref: 'CreditTransaction' },

    // Fields for escalation and assignment
    assignedTo: { type: String }, // Email of the assignee (Reseller or Admin)
    isEscalated: { type: Boolean, default: false }
  },
  { timestamps: true }
);

const Ticket = mongoose.model("Ticket", ticketSchema);

export default Ticket;
