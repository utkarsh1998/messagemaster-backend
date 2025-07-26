import mongoose from "mongoose";

const creditTransactionSchema = new mongoose.Schema(
  {
    to: {
      type: String,
      required: true,
    },
    by: {
      type: String,
      required: true,
    },
    creditType: {
      type: String,
      required: true,
    },
    count: {
      type: Number,
      required: true,
    },
    rate: {
      // ✅ FIX: Rate is no longer universally required. It will be validated by the server logic instead.
      type: Number,
      default: 0,
    },
    total: {
      type: Number,
    },
    type: {
      type: String,
      enum: ["Added", "Removed"],
      required: true,
    },
    reason: {
      type: String,
      default: "",
    },
  },
  { timestamps: true }
);

// Mongoose pre-save hook to auto-calculate 'total'
creditTransactionSchema.pre("save", function (next) {
  if (this.isModified("count") || this.isModified("rate")) {
    this.total = this.count * this.rate;
  }
  next();
});

const CreditTransaction = mongoose.model(
  "CreditTransaction",
  creditTransactionSchema
);

export default CreditTransaction;
