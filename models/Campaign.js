import mongoose from "mongoose";

const reportEntrySchema = new mongoose.Schema({
  recipient: { type: String, required: true },
  status: { type: String, enum: ["Delivered", "Failed", "Pending"], default: "Pending" },
});

const campaignSchema = new mongoose.Schema(
  {
    userEmail: {
      type: String,
      required: true,
    },
    createdBy: {
      type: String,
      required: true,
    },
    creditType: {
      type: String,
      required: true,
    },
    to: {
      type: String,
      required: true,
    },
    message: {
      type: String,
      required: true,
    },
    images: { type: [String], default: [] },
    pdf: { type: String, default: "" },
    video: { type: String, default: "" },
    audio: { type: String, default: "" },
    dp: { type: String, default: "" },
    singleCreative: { type: String, default: "" },
    ctaCall: { type: String, default: "" },
    ctaCallText: { type: String, default: "" },
    ctaURL: { type: String, default: "" },
    ctaURLText: { type: String, default: "" },
    status: {
      type: String,
      enum: [
        "Submitted", "Pending Approval", "Approved", "Processing",
        "Completed", "Report Generated", "Rejected",
        // ✅ NEW STATUSES ADDED
        "Cancellation Requested", "Cancelled"
      ],
      default: "Pending Approval",
    },
    reason: { type: String, default: "" },
    
    // ✅ NEW FIELD for storing the admin's reason for rejecting a cancellation.
    cancellationRejectionReason: {
        type: String,
        default: ""
    },

    report: [reportEntrySchema],
    reportUploadedAt: { type: Date },
    reportUploadedBy: { type: String },
  },
  { timestamps: true }
);

const Campaign = mongoose.model("Campaign", campaignSchema);

export default Campaign;
