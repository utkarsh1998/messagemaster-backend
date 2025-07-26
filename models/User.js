import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["Admin", "Reseller", "Sub-Reseller", "User"],
      required: true,
    },
    status: {
      type: String,
      enum: ["Active", "Blocked"],
      default: "Active",
    },
    createdBy: {
      type: String, // email of creator
    },
    reseller: {
      type: String, // email of the top-level reseller
    },
    ownNumber: {
      type: String,
    },
    // ✅ NEW: Whitelabel fields for Resellers
    companyName: {
      type: String,
      default: '', // Default to an empty string
    },
    companyLogo: {
        type: String, // Will store the path to the uploaded logo
        default: '',
    },
  },
  { timestamps: true }
);

// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Middleware to hash password before saving a new user
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

const User = mongoose.model("User", userSchema);

export default User;
