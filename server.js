import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import csv from "csv-parser";
import fs from "fs";
import XLSX from 'xlsx';
import mongoose from 'mongoose';
import nodemailer from "nodemailer";
import { BSON } from 'bson';

import connectDB from "./config/db.js";
import User from "./models/User.js";
import CreditTransaction from "./models/CreditTransaction.js";
import Campaign from "./models/Campaign.js";
import Ticket from "./models/Ticket.js";
import Announcement from "./models/Announcement.js";
import Notification from "./models/Notification.js";
import Otp from "./models/Otp.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/backups", express.static(path.join(__dirname, "backups")));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

const protect = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ message: "Not authorized, token failed" });
    }
  } else {
    res.status(401).json({ message: "Not authorized, no token" });
  }
};

const adminOnly = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
        next();
    } else {
        res.status(403).json({ message: 'Not authorized as an admin.' });
    }
};

// Helper function to create notifications up the hierarchy
const createHierarchicalNotification = async (userEmail, message, link, eventType) => {
    try {
        let currentUser = await User.findOne({ email: userEmail }).select('createdBy reseller');
        const recipients = new Set();

        if (currentUser && currentUser.createdBy) {
            recipients.add(currentUser.createdBy);
        }

        if (currentUser && currentUser.reseller) {
            recipients.add(currentUser.reseller);
        }
        
        const admin = await User.findOne({ role: 'Admin' }).select('email');
        if (admin) {
            recipients.add(admin.email);
        }

        for (const recipientEmail of recipients) {
            await Notification.create({
                userEmail: recipientEmail,
                message,
                link,
                eventType,
            });
        }
    } catch (error) {
        console.error('Error creating hierarchical notification:', error);
    }
};


// --- API ROUTES ---

app.get("/", (req, res) => res.send("✅ API is running..."));

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && (await user.matchPassword(password))) {
      if (user.status === "Blocked") return res.status(403).json({ message: "Account is blocked." });

      let currentUserForBranding = user;
      while (!currentUserForBranding.companyName && currentUserForBranding.createdBy) {
          const creator = await User.findOne({ email: currentUserForBranding.createdBy }).select('companyName companyLogo createdBy');
          if (!creator) break;
          currentUserForBranding = creator;
      }
      const branding = {
          companyName: currentUserForBranding.companyName || 'MessageMaster',
          companyLogo: currentUserForBranding.companyLogo || ''
      };

      const token = jwt.sign({ id: user._id, email: user.email, role: user.role, reseller: user.reseller }, process.env.JWT_SECRET, { expiresIn: "7d" });
      
      const userPayload = { 
          id: user._id, name: user.name, email: user.email, role: user.role, 
          createdBy: user.createdBy, reseller: user.reseller, ownNumber: user.ownNumber, 
          createdAt: user.createdAt,
          branding
      };

      res.json({ token, user: userPayload });
    } else {
      res.status(401).json({ message: "Invalid email or password" });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error during login" });
  }
});

// --- Users API ---
app.get("/api/users", protect, async (req, res) => {
  try {
    const { role, email } = req.user;
    let filter = {};
    if (req.headers['x-admin-fetch'] === 'true' && role === 'Admin') {
        // No filter, admin gets all users
    } else if (role === "Reseller") {
        filter = { $or: [{ createdBy: email }, { reseller: email }] };
    } else if (role === "Sub-Reseller") {
        filter = { createdBy: email };
    }
    const users = await User.find(filter).select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "Server error fetching users" });
  }
});

app.get("/api/users/profile/:id", protect, async (req, res) => {
    try {
        const targetUser = await User.findById(req.params.id).select("-password");
        if (!targetUser) {
            return res.status(404).json({ message: "User not found" });
        }
        const requester = await User.findById(req.user.id);
        const isOwner = requester.id === targetUser.id;
        const isAdmin = requester.role === 'Admin';
        const isManager = requester.email === targetUser.createdBy || requester.email === targetUser.reseller;

        if (isOwner || isAdmin || isManager) {
            res.json(targetUser);
        } else {
            return res.status(403).json({ message: "Not authorized to view this profile." });
        }
    } catch (error) {
        res.status(500).json({ message: "Server error fetching user profile." });
    }
});

app.post("/api/users", protect, async (req, res) => {
  try {
    const createdBy = req.user.email; 
    const creatorRole = req.user.role;
    const { name, email, password, role, ...otherDetails } = req.body;
    
    delete otherDetails.createdBy;
    delete otherDetails.reseller;
    
    if (!name || !email) return res.status(400).json({ message: "Name and Email are required" });
    
    const userExists = await User.findOne({ email });
    if (userExists) {
        return res.status(400).json({ message: "A user with this email already exists." });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password || "123456", salt);
    
    let reseller = null; 
    if (creatorRole === 'Reseller') reseller = req.user.email;
    else if (creatorRole === 'Sub-Reseller') reseller = req.user.reseller;

    const newUserPayload = { name, email, password: hashedPassword, role, createdBy, reseller, ...otherDetails };
    const user = await User.create(newUserPayload);
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ message: error.message || "An unexpected error occurred." });
  }
});

app.put("/api/users/update/:id", protect, upload.single('companyLogo'), async (req, res) => {
    try {
        const { name, email, role, status, password, ownNumber, companyName } = req.body;
        
        const updateData = { name, email, role, status, ownNumber };

        if (req.user.role === 'Admin') {
            updateData.companyName = companyName;
            if (req.file) {
                updateData.companyLogo = `/uploads/${req.file.filename}`;
            }
        }

        if (password) {
            const salt = await bcrypt.genSalt(10);
            updateData.password = await bcrypt.hash(password, salt);
        }

        const user = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(user);
    } catch (error) {
        res.status(400).json({ message: "Error updating user" });
    }
});

app.put("/api/users/change-password", protect, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);

        if (user && (await user.matchPassword(currentPassword))) {
            user.password = newPassword;
            await user.save();
            res.json({ message: "Password updated successfully." });
        } else {
            res.status(401).json({ message: "Invalid current password." });
        }
    } catch (error) {
        res.status(500).json({ message: "Server error changing password." });
    }
});

app.put("/api/users/:id", protect, async (req, res) => {
    try {
        const { status } = req.body;
        const user = await User.findByIdAndUpdate(req.params.id, { status }, { new: true });
        res.json(user);
    } catch (error) {
        res.status(400).json({ message: "Error updating user status" });
    }
});


// --- Credits API ---
app.get("/api/credits", protect, async (req, res) => {
  try {
    const { role, email } = req.user;
    let filter = {};
    if (role === "Reseller") {
        const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
        const managedEmails = managedUsers.map(u => u.email).concat(email);
        filter = { to: { $in: managedEmails } };
    } else if (role === "Sub-Reseller" || role === "User") {
        filter = { to: email };
    }
    const credits = await CreditTransaction.find(filter).sort({ createdAt: -1 });
    res.json(credits);
  } catch (error) {
    res.status(500).json({ message: "Server error fetching credits" });
  }
});

app.get("/api/credits/user/:email", protect, async (req, res) => {
    try {
        const credits = await CreditTransaction.find({ to: req.params.email }).sort({ createdAt: -1 });
        res.json(credits);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching user credits." });
    }
});

app.post("/api/credits", protect, async (req, res) => {
  try {
    const { to, creditType, count, rate, type, reason } = req.body;
    
    if (!to || !creditType || !type) {
      return res.status(400).json({ message: "User, Credit Type, and Transaction Type are required." });
    }
    if (typeof count !== 'number' || count <= 0) {
        return res.status(400).json({ message: "Credit count must be a number greater than 0." });
    }
    if (type === 'Added' && (typeof rate !== 'number' || rate <= 0)) {
        return res.status(400).json({ message: "A rate greater than 0 is required when adding credits." });
    }

    const newTx = await CreditTransaction.create({ to, by: req.user.email, creditType, count, rate: rate || 0, type, reason });
    res.status(201).json(newTx);
  } catch (error) {
    console.error("Credit creation error:", error);
    res.status(400).json({ message: "Error creating credit transaction" });
  }
});

// --- Campaigns API ---
app.get("/api/campaigns", protect, async (req, res) => {
  try {
    const { role, email } = req.user;
    let filter = {};
    if (role === "Reseller") {
        const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
        const managedEmails = managedUsers.map(u => u.email).concat(email);
        filter = { userEmail: { $in: managedEmails } };
    } else if (role === "Sub-Reseller" || role === "User") {
        filter = { userEmail: email };
    }
    const campaigns = await Campaign.find(filter).sort({ createdAt: -1 });
    res.json(campaigns);
  } catch (error) {
    res.status(500).json({ message: "Server error fetching campaigns" });
  }
});

app.get("/api/campaigns/user/:email", protect, async (req, res) => {
    try {
        const campaigns = await Campaign.find({ userEmail: req.params.email }).sort({ createdAt: -1 });
        res.json(campaigns);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching user campaigns." });
    }
});

app.post("/api/campaigns", protect, upload.fields([
    { name: "images", maxCount: 3 }, { name: "pdf", maxCount: 1 },
    { name: "audio", maxCount: 1 }, { name: "video", maxCount: 1 },
    { name: "dp", maxCount: 1 }, { name: "singleCreative", maxCount: 1 }
]), async (req, res) => {
    try {
        const { to, creditType, message, userEmail, ...ctaDetails } = req.body;
        const createdBy = req.user.email;
        const targetUserEmail = userEmail || createdBy;
        const creditRecords = await CreditTransaction.find({ to: targetUserEmail, creditType });
        const availableCredits = creditRecords.reduce((acc, tx) => acc + (tx.type === 'Added' ? tx.count : -tx.count), 0);
        const messageCount = to.split(",").length;
        if (availableCredits < messageCount) {
            return res.status(400).json({ message: `Insufficient credits for type ${creditType}.` });
        }
        await CreditTransaction.create({ to: targetUserEmail, by: "System", creditType, count: messageCount, rate: 0, type: "Removed", reason: `Campaign Sent by ${createdBy}` });
        const images = req.files["images"] ? req.files["images"].map((f) => `/uploads/${f.filename}`) : [];
        const newCampaignData = { to, creditType, message, userEmail: targetUserEmail, createdBy, ...ctaDetails, images,
            pdf: req.files["pdf"] ? `/uploads/${req.files["pdf"][0].filename}` : "",
            audio: req.files["audio"] ? `/uploads/${req.files["audio"][0].filename}` : "",
            video: req.files["video"] ? `/uploads/${req.files["video"][0].filename}` : "",
            dp: req.files["dp"] ? `/uploads/${req.files["dp"][0].filename}` : "",
            singleCreative: req.files["singleCreative"] ? `/uploads/${req.files["singleCreative"][0].filename}` : "",
        };
        const newCampaign = await Campaign.create(newCampaignData);
        
        const notificationMessage = `New campaign submitted by ${newCampaign.userEmail}.`;
        await createHierarchicalNotification(newCampaign.userEmail, notificationMessage, `/campaigns`, 'NewCampaign');

        res.status(201).json(newCampaign);
    } catch (error) {
        res.status(400).json({ message: "Error creating campaign" });
    }
});

app.post("/api/campaigns/:id/upload-report", protect, upload.single('reportFile'), async (req, res) => {
    try {
        if (req.user.role !== 'Admin') {
            return res.status(403).json({ message: "Not authorized." });
        }
        if (!req.file) {
            return res.status(400).json({ message: "No report file was uploaded." });
        }
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign) {
            return res.status(404).json({ message: "Campaign not found." });
        }
        const originalRecipients = new Set(campaign.to.split(',').map(num => num.trim()));
        const reportData = [];
        const filePath = req.file.path;
        fs.createReadStream(filePath)
            .pipe(csv())
            .on('data', (row) => {
                if (originalRecipients.has(row.recipient?.trim())) {
                    reportData.push(row);
                }
            })
            .on('end', async () => {
                try {
                    campaign.report = reportData;
                    campaign.status = "Report Generated";
                    campaign.reportUploadedAt = new Date();
                    campaign.reportUploadedBy = req.user.email;
                    await campaign.save();
                    fs.unlinkSync(filePath);
                    res.json({ message: "Report uploaded successfully.", campaign });
                } catch (dbError) {
                    res.status(500).json({ message: "Error saving the report to the database." });
                }
            })
            .on('error', (streamError) => {
                res.status(500).json({ message: "Failed to process the uploaded CSV file." });
            });
    } catch (error) {
        res.status(500).json({ message: "Server error while uploading report." });
    }
});

app.delete("/api/campaigns/:id", protect, async (req, res) => {
    try {
        const { id } = req.params;
        const campaign = await Campaign.findById(id);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        const creditsToRefund = campaign.to.split(",").length;
        await CreditTransaction.create({ to: campaign.userEmail, by: "System", creditType: campaign.creditType, count: creditsToRefund, rate: 0, type: "Added", reason: `Refund for deleted campaign ${id}` });
        await Campaign.findByIdAndDelete(id);
        res.json({ message: "Campaign deleted and credits refunded" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting campaign" });
    }
});

app.put("/api/campaigns/status/:id", protect, async (req, res) => {
    try {
        const { status } = req.body;
        const campaign = await Campaign.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        res.json(campaign);
    } catch (error) {
        res.status(500).json({ message: "Error updating campaign status" });
    }
});

app.put("/api/campaigns/:id/request-cancellation", protect, async (req, res) => {
    try {
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (campaign.createdBy !== req.user.email) {
            return res.status(403).json({ message: "You are not authorized to modify this campaign." });
        }
        campaign.status = "Cancellation Requested";
        await campaign.save();
        
        const message = `Campaign cancellation requested by ${req.user.email}.`;
        await createHierarchicalNotification(req.user.email, message, `/campaigns`, 'CampaignStatusUpdate');

        res.json(campaign);
    } catch (error) {
        res.status(500).json({ message: "Server error while requesting cancellation." });
    }
});

app.put("/api/campaigns/:id/handle-cancellation", protect, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: "Not authorized" });
    try {
        const { action, reason } = req.body;
        const campaign = await Campaign.findById(req.params.id);
        if (!campaign) return res.status(404).json({ message: "Campaign not found" });
        if (action === 'approve') {
            campaign.status = "Cancelled";
            const creditsToRefund = campaign.to.split(",").length;
            await CreditTransaction.create({ to: campaign.userEmail, by: req.user.email, creditType: campaign.creditType, count: creditsToRefund, rate: 0, type: "Added", reason: `Refund for cancelled campaign ${campaign._id}` });
        } else if (action === 'reject') {
            campaign.status = "Approved";
            campaign.cancellationRejectionReason = reason;
        }
        await campaign.save();
        res.json(campaign);
    } catch (error) {
        res.status(500).json({ message: "Server error while handling cancellation." });
    }
});

// --- Ticket System API ---
app.get("/api/tickets", protect, async (req, res) => {
    try {
        const { role, email } = req.user;
        let filter = {};
        if (role === 'Admin') {
            filter = {};
        } else if (role === 'Reseller') {
            const managedUsers = await User.find({ reseller: email }, 'email');
            const managedEmails = managedUsers.map(u => u.email);
            filter = { $or: [{ userEmail: email }, { userEmail: { $in: managedEmails } }, { assignedTo: email }] };
        } else {
            filter = { userEmail: email };
        }
        const tickets = await Ticket.find(filter).sort({ updatedAt: -1 });
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching tickets." });
    }
});

app.post("/api/tickets", protect, upload.array('attachments', 5), async (req, res) => {
    try {
        const { subject, description, issueType, relatedCampaign, relatedUser, relatedTransaction } = req.body;
        const userEmail = req.user.email;
        if (!subject || !description) {
            return res.status(400).json({ message: "Subject and description are required." });
        }
        const attachments = req.files ? req.files.map(f => `/${f.path}`) : [];
        const creator = await User.findOne({ email: userEmail });
        let assignedTo = 'Admin';
        if (creator && creator.createdBy) {
            const creatorUser = await User.findOne({ email: creator.createdBy });
            if (creatorUser && creatorUser.role === 'Admin') {
                assignedTo = 'Admin';
            } else {
                assignedTo = creator.createdBy;
            }
        }
        const newTicketData = { userEmail, subject, description, attachments, issueType, assignedTo };
        if (relatedCampaign) newTicketData.relatedCampaign = relatedCampaign;
        if (relatedUser) newTicketData.relatedUser = relatedUser;
        if (relatedTransaction) newTicketData.relatedTransaction = relatedTransaction;
        const newTicket = await Ticket.create(newTicketData);

        const message = `New support ticket created by ${userEmail}.`;
        await createHierarchicalNotification(userEmail, message, `/tickets`, 'NewTicket');
        
        res.status(201).json(newTicket);
    } catch (error) {
        console.error("--- TICKET CREATION FAILED ---", error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ message: `Validation Error: ${error.message}` });
        }
        res.status(500).json({ message: "Server error creating ticket." });
    }
});

app.put("/api/tickets/:id/reply", protect, async (req, res) => {
    try {
        const { message } = req.body;
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) return res.status(404).json({ message: "Ticket not found." });
        if (req.user.role !== 'Admin' && ticket.userEmail !== req.user.email && ticket.assignedTo !== req.user.email) {
            return res.status(403).json({ message: "Not authorized to reply." });
        }
        ticket.replies.push({ userEmail: req.user.email, message, createdAt: new Date() });
        if (ticket.status === 'Open') ticket.status = "In Progress";
        await ticket.save();

        const recipient = ticket.userEmail === req.user.email ? ticket.assignedTo : ticket.userEmail;
        await Notification.create({
            userEmail: recipient,
            message: `New reply on your ticket: "${ticket.subject}"`,
            link: `/tickets`,
            eventType: 'TicketReply'
        });

        res.json(ticket);
    } catch (error) {
        res.status(500).json({ message: "Server error adding reply." });
    }
});

app.put("/api/tickets/:id/status", protect, async (req, res) => {
    try {
        if (req.user.role !== 'Admin' && req.user.email !== req.body.assignedTo) return res.status(403).json({ message: "Not authorized." });
        const { status } = req.body;
        const ticket = await Ticket.findByIdAndUpdate(req.params.id, { status }, { new: true });
        if (!ticket) return res.status(404).json({ message: "Ticket not found." });
        res.json(ticket);
    } catch (error) {
        res.status(500).json({ message: "Server error updating status." });
    }
});

app.put("/api/tickets/:id/escalate", protect, async (req, res) => {
    try {
        const ticket = await Ticket.findById(req.params.id);
        if (!ticket) return res.status(404).json({ message: "Ticket not found." });
        ticket.isEscalated = true;
        ticket.assignedTo = 'Admin';
        ticket.status = 'Escalated';
        await ticket.save();
        res.json(ticket);
    } catch(error) {
        res.status(500).json({ message: "Error escalating ticket." });
    }
});

app.put("/api/tickets/:id/assign", protect, async (req, res) => {
    try {
        if (req.user.role !== 'Admin') return res.status(403).json({ message: "Not authorized." });
        const { assignee } = req.body;
        const ticket = await Ticket.findByIdAndUpdate(req.params.id, { assignedTo: assignee, isEscalated: false }, { new: true });
        if (!ticket) return res.status(404).json({ message: "Ticket not found." });
        res.json(ticket);
    } catch(error) {
        res.status(500).json({ message: "Error assigning ticket." });
    }
});


// --- Announcement System API ---
app.get("/api/announcements", protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });
        
        const baseConditions = {
            $or: [{ expiryDate: { $exists: false } }, { expiryDate: null }, { expiryDate: { $gte: new Date() } }],
            seenBy: { $nin: [user.email] }
        };

        const visibilityConditions = {
            $or: [
                { 'visibility.type': 'all' },
                { 'visibility.type': 'specific', 'visibility.targets': user.email },
                { 'visibility.type': 'reseller', 'visibility.targets': user.reseller || user.email }
            ]
        };
        const announcements = await Announcement.find({ $and: [baseConditions, visibilityConditions] }).sort({ createdAt: -1 });
        res.json(announcements);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching announcements." });
    }
});

app.get("/api/announcements/all", protect, async (req, res) => {
    if (req.user.role !== 'Admin') return res.status(403).json({ message: "Not authorized." });
    try {
        const announcements = await Announcement.find({}).sort({ createdAt: -1 });
        res.json(announcements);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching all announcements." });
    }
});

app.get("/api/announcements/history", protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: "User not found." });

        const visibilityConditions = {
            $or: [
                { 'visibility.type': 'all' },
                { 'visibility.type': 'specific', 'visibility.targets': user.email },
                { 'visibility.type': 'reseller', 'visibility.targets': user.reseller || user.email }
            ]
        };
        const announcements = await Announcement.find(visibilityConditions).sort({ createdAt: -1 });
        res.json(announcements);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching announcement history." });
    }
});

app.post("/api/announcements", protect, upload.single('image'), async (req, res) => {
    try {
        if (req.user.role !== 'Admin') return res.status(403).json({ message: "Not authorized to create announcements." });
        
        const { title, message, link, expiryDate, visibilityType, visibilityTargets } = req.body;
        const image = req.file ? `/uploads/${req.file.filename}` : "";
        
        const newAnnouncement = await Announcement.create({
            title, message, link, expiryDate, image,
            visibility: { type: visibilityType, targets: visibilityTargets ? visibilityTargets.split(',') : [] },
            createdBy: req.user.email
        });
        res.status(201).json(newAnnouncement);
    } catch (error) {
        res.status(500).json({ message: "Server error creating announcement." });
    }
});

app.put("/api/announcements/:id/seen", protect, async (req, res) => {
    try {
        const announcement = await Announcement.findById(req.params.id);
        if (!announcement) return res.status(404).json({ message: "Announcement not found." });
        if (!announcement.seenBy.includes(req.user.email)) {
            announcement.seenBy.push(req.user.email);
            await announcement.save();
        }
        res.json({ message: "Announcement marked as seen." });
    } catch (error) {
        res.status(500).json({ message: "Server error marking announcement as seen." });
    }
});

app.delete("/api/announcements/:id", protect, async (req, res) => {
    try {
        if (req.user.role !== 'Admin') return res.status(403).json({ message: "Not authorized to delete announcements." });
        await Announcement.findByIdAndDelete(req.params.id);
        res.json({ message: "Announcement deleted." });
    } catch (error) {
        res.status(500).json({ message: "Server error deleting announcement." });
    }
});

app.get("/api/announcements/:id/status", protect, async (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: "Not authorized." });
    }
    try {
        const announcement = await Announcement.findById(req.params.id);
        if (!announcement) {
            return res.status(404).json({ message: "Announcement not found." });
        }

        const seenByEmails = new Set(announcement.seenBy);
        let targetUserQuery = {};

        switch (announcement.visibility.type) {
            case 'all':
                targetUserQuery = {};
                break;
            case 'specific':
                targetUserQuery = { email: { $in: announcement.visibility.targets } };
                break;
            case 'reseller':
                const resellerEmail = announcement.visibility.targets[0];
                targetUserQuery = { $or: [{ email: resellerEmail }, { reseller: resellerEmail }] };
                break;
            default:
                return res.json({ seenUsers: [], pendingUsers: [] });
        }
        
        const allTargetedUsers = await User.find(targetUserQuery).select('name email role');

        const seenUsers = [];
        const pendingUsers = [];

        allTargetedUsers.forEach(user => {
            if (seenByEmails.has(user.email)) {
                seenUsers.push(user);
            } else {
                pendingUsers.push(user);
            }
        });

        res.json({ seenUsers, pendingUsers });

    } catch (error) {
        res.status(500).json({ message: "Server error fetching announcement status." });
    }
});


// --- Analytics API ---
app.get("/api/analytics", protect, async (req, res) => {
    try {
        const { role, email } = req.user;
        let userFilter = {}, creditFilter = {}, campaignFilter = {};
        if (role === "Reseller") {
            const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
            const managedEmails = managedUsers.map(u => u.email).concat(email);
            userFilter = { email: { $in: managedEmails.filter(e => e !== email) }};
            creditFilter = { to: { $in: managedEmails } };
            campaignFilter = { userEmail: { $in: managedEmails } };
        } else if (role === "Sub-Reseller" || role === "User") {
            userFilter = { createdBy: email };
            creditFilter = { to: email };
            campaignFilter = { userEmail: email };
        }
        const [totalUsers, activeUsers, added, removed, totalCampaigns] = await Promise.all([
            User.countDocuments(userFilter),
            User.countDocuments({ ...userFilter, status: "Active" }),
            CreditTransaction.aggregate([{ $match: { ...creditFilter, type: "Added" } }, { $group: { _id: null, total: { $sum: "$count" } } }]),
            CreditTransaction.aggregate([{ $match: { ...creditFilter, type: "Removed" } }, { $group: { _id: null, total: { $sum: "$count" } } }]),
            Campaign.countDocuments(campaignFilter),
        ]);
        res.json({ users: { total: totalUsers, active: activeUsers }, credits: { added: added[0]?.total || 0, removed: removed[0]?.total || 0 }, campaigns: { total: totalCampaigns } });
    } catch (error) {
        res.status(500).json({ message: "Analytics error" });
    }
});

app.get("/api/analytics/credits-trend", protect, async (req, res) => {
    try {
        const { role, email } = req.user;
        let creditFilter = {};
        if (role !== 'Admin') {
            const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
            const managedEmails = managedUsers.map(u => u.email).concat(email);
            creditFilter = { to: { $in: managedEmails } };
        }
        const trend = await CreditTransaction.aggregate([
            { $match: creditFilter },
            { $group: { _id: { date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, type: "$type" }, total: { $sum: "$count" } } },
            { $group: { _id: "$_id.date", Added: { $sum: { $cond: [{ $eq: ["$_id.type", "Added"] }, "$total", 0] } }, Removed: { $sum: { $cond: [{ $eq: ["$_id.type", "Removed"] }, "$total", 0] } } } },
            { $sort: { _id: 1 } },
        ]);
        res.json(trend.map(t => ({ date: t._id, Added: t.Added, Removed: t.Removed })));
    } catch (error) {
        res.status(500).json({ message: "Error fetching credit trends" });
    }
});

app.get("/api/analytics/credit-types", protect, async (req, res) => {
    try {
        const { role, email } = req.user;
        let creditFilter = { type: 'Removed' };
        if (role !== 'Admin') {
            const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
            const managedEmails = managedUsers.map(u => u.email).concat(email);
            creditFilter.to = { $in: managedEmails };
        }
        const creditTypes = await CreditTransaction.aggregate([
            { $match: creditFilter },
            { $group: { _id: "$creditType", value: { $sum: "$count" } } },
            { $sort: { value: -1 } },
        ]);
        res.json(creditTypes.map((c) => ({ name: c._id, value: c.value })));
    } catch (error) {
        res.status(500).json({ message: "Error fetching credit types" });
    }
});

app.get("/api/analytics/campaign-types", protect, async (req, res) => {
    try {
        const { role, email } = req.user;
        let campaignFilter = {};
        if (role !== 'Admin') {
            const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
            const managedEmails = managedUsers.map(u => u.email).concat(email);
            campaignFilter.userEmail = { $in: managedEmails };
        }
        const campaignTypes = await Campaign.aggregate([
            { $match: campaignFilter },
            { $group: { _id: "$creditType", count: { $sum: { $size: { $split: ["$to", ","] } } } } },
            { $sort: { count: -1 } },
        ]);
        res.json(campaignTypes.map((c) => ({ name: c._id, count: c.count })));
    } catch (error) {
        res.status(500).json({ message: "Error fetching campaign types" });
    }
});

app.get("/api/analytics/top-users", protect, async (req, res) => {
    try {
        const { role, email } = req.user;
        let creditFilter = { type: 'Removed' };
        if (role !== 'Admin') {
            const managedUsers = await User.find({ $or: [{ createdBy: email }, { reseller: email }] }, 'email');
            const managedEmails = managedUsers.map(u => u.email).concat(email);
            creditFilter.to = { $in: managedEmails };
        }
        const topUsers = await CreditTransaction.aggregate([
            { $match: creditFilter },
            { $group: { _id: "$to", used: { $sum: "$count" } } },
            { $sort: { used: -1 } },
            { $limit: 7 },
        ]);
        res.json(topUsers.map(u => ({ name: u._id, used: u.used })));
    } catch (error) {
        res.status(500).json({ message: "Error fetching top users" });
    }
});

// ===================================================
// WHITELABEL API
// ===================================================
app.get("/api/whitelabel/settings", protect, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('companyName companyLogo');
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching whitelabel settings." });
    }
});

app.post("/api/whitelabel/settings", protect, upload.single('companyLogo'), async (req, res) => {
    try {
        const { companyName } = req.body;
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        if (user.role !== 'Reseller' && user.role !== 'Sub-Reseller') {
            return res.status(403).json({ message: "Only Resellers and Sub-Resellers can set whitelabel settings." });
        }

        user.companyName = companyName;
        if (req.file) {
            user.companyLogo = `/uploads/${req.file.filename}`;
        }

        await user.save();
        res.json({ message: "Settings updated successfully.", user: { companyName: user.companyName, companyLogo: user.companyLogo } });
    } catch (error) {
        res.status(500).json({ message: "Server error updating whitelabel settings." });
    }
});

app.get("/api/whitelabel/my-branding", protect, async (req, res) => {
    try {
        let currentUser = await User.findById(req.user.id).select('companyName companyLogo createdBy');
        if (!currentUser) {
            return res.status(404).json({ message: "User not found." });
        }

        while (!currentUser.companyName && currentUser.createdBy) {
            const creator = await User.findOne({ email: currentUser.createdBy }).select('companyName companyLogo createdBy');
            if (!creator) break;
            currentUser = creator;
        }

        res.json({
            companyName: currentUser.companyName || 'MessageMaster',
            companyLogo: currentUser.companyLogo || ''
        });

    } catch (error) {
        res.status(500).json({ message: "Server error fetching branding." });
    }
});

// ===================================================
// NOTIFICATION API
// ===================================================
app.get('/api/notifications', protect, async (req, res) => {
    try {
        const notifications = await Notification.find({ userEmail: req.user.email, isRead: false })
            .sort({ createdAt: -1 });
        res.json(notifications);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch notifications.' });
    }
});

app.put('/api/notifications/:id/read', protect, async (req, res) => {
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, userEmail: req.user.email },
            { isRead: true }
        );
        if (!notification) {
            return res.status(404).json({ message: 'Notification not found.' });
        }
        res.json({ message: 'Notification marked as read.' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to mark notification as read.' });
    }
});

// ===================================================
// BACKUP & DATA MANAGEMENT API (ADMIN ONLY)
// ===================================================
app.post('/api/backup/generate-download', protect, adminOnly, async (req, res) => {
    try {
        const users = await User.find({}).lean();
        const creditTransactions = await CreditTransaction.find({}).lean();
        const campaigns = await Campaign.find({}).lean();
        const tickets = await Ticket.find({}).lean();

        const usersWithCreditBalance = users.map(user => {
            const userTransactions = creditTransactions.filter(t => t.to === user.email);
            const balance = userTransactions.reduce((acc, tx) => acc + (tx.type === 'Added' ? tx.count : -tx.count), 0);
            return {
                Name: user.name,
                Email: user.email,
                Role: user.role,
                Status: user.status,
                'Created By': user.createdBy || 'Admin',
                'Top-Level Reseller': user.reseller,
                'Current Credit Balance': balance,
                'Created At': user.createdAt,
            };
        });

        const workbook = XLSX.utils.book_new();
        const usersSheet = XLSX.utils.json_to_sheet(usersWithCreditBalance);
        const transactionsSheet = XLSX.utils.json_to_sheet(creditTransactions);
        const campaignsSheet = XLSX.utils.json_to_sheet(campaigns);
        const ticketsSheet = XLSX.utils.json_to_sheet(tickets);

        XLSX.utils.book_append_sheet(workbook, usersSheet, "Users & Balances");
        XLSX.utils.book_append_sheet(workbook, transactionsSheet, "Credit Transactions");
        XLSX.utils.book_append_sheet(workbook, campaignsSheet, "Campaigns");
        XLSX.utils.book_append_sheet(workbook, ticketsSheet, "Support Tickets");

        const backupDir = path.join(__dirname, 'backups');
        if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir);
        
        const timestamp = new Date().toISOString().replace(/:/g, '-');
        const filename = `backup-${timestamp}.xlsx`;
        const filepath = path.join(backupDir, filename);
        
        XLSX.writeFile(workbook, filepath);
        
        setTimeout(() => {
            if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
        }, 300000); 

        res.json({ downloadUrl: `/backups/${filename}` });
    } catch (error) {
        console.error("Backup Error:", error);
        res.status(500).json({ message: 'Server error during backup file generation.' });
    }
});

app.post('/api/backup/save-to-server', protect, adminOnly, async (req, res) => {
    try {
        const backupData = {
            users: await User.find({}),
            creditTransactions: await CreditTransaction.find({}),
            campaigns: await Campaign.find({}),
            tickets: await Ticket.find({}),
            announcements: await Announcement.find({}),
            notifications: await Notification.find({}),
        };
        
        const backupDir = path.join(__dirname, 'backups');
        if (!fs.existsSync(backupDir)) {
            fs.mkdirSync(backupDir);
        }
        
        const timestamp = new Date().toISOString().replace(/:/g, '-');
        const filename = `backup-${timestamp}.json`;
        const filepath = path.join(backupDir, filename);
        
        fs.writeFileSync(filepath, JSON.stringify(backupData, null, 2));
        
        res.json({ message: `Backup successfully saved to server at ${filepath}` });
    } catch (error) {
        res.status(500).json({ message: 'Server error saving backup.' });
    }
});

app.delete('/api/data/cleanup', protect, adminOnly, async (req, res) => {
    try {
        const { dataType, fromDate, toDate } = req.body;
        const startDate = new Date(fromDate);
        const endDate = new Date(toDate);
        endDate.setHours(23, 59, 59, 999);

        let count = 0;

        switch (dataType) {
            case 'campaigns':
                const campaignsToDelete = await Campaign.find({ createdAt: { $gte: startDate, $lte: endDate } });
                for (const campaign of campaignsToDelete) {
                    const filesToDelete = [campaign.dp, campaign.singleCreative, campaign.pdf, campaign.video, campaign.audio, ...(campaign.images || [])];
                    for (const file of filesToDelete) {
                        if (file) {
                            const filepath = path.join(__dirname, 'uploads', path.basename(file));
                            if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
                        }
                    }
                    await Campaign.findByIdAndDelete(campaign._id);
                }
                count = campaignsToDelete.length;
                break;

            case 'users':
                const usersToDelete = await User.find({ role: { $ne: 'Admin' }, createdAt: { $gte: startDate, $lte: endDate } });
                for (const user of usersToDelete) {
                    await CreditTransaction.deleteMany({ to: user.email });
                    await Campaign.deleteMany({ userEmail: user.email });
                    await Ticket.deleteMany({ userEmail: user.email });
                    await User.findByIdAndDelete(user._id);
                }
                count = usersToDelete.length;
                break;

            case 'transactions':
                const result = await CreditTransaction.deleteMany({ createdAt: { $gte: startDate, $lte: endDate } });
                count = result.deletedCount;
                break;

            default:
                return res.status(400).json({ message: 'Invalid data type for cleanup.' });
        }

        res.json({ message: `${count} ${dataType} records have been permanently deleted.` });
    } catch (error) {
        console.error("Cleanup Error:", error);
        res.status(500).json({ message: 'Error during data cleanup.' });
    }
});

// ===================================================
// FORGOT PASSWORD API
// ===================================================

const setupEmailTransporter = async () => {
    try {
        const testAccount = await nodemailer.createTestAccount();
        console.log("📧 Nodemailer test account created:");
        console.log("User:", testAccount.user);
        console.log("Pass:", testAccount.pass);
        console.log("Preview URL: %s", nodemailer.getTestMessageUrl({ from: 'forgot-password@messagemaster.com', to: 'test@example.com', subject: 'Test', text: 'Hello' }));

        return nodemailer.createTransport({
            host: "smtp.ethereal.email",
            port: 587,
            secure: false,
            auth: {
                user: testAccount.user,
                pass: testAccount.pass,
            },
        });
    } catch (error) {
        console.error("Failed to create nodemailer test account:", error);
        return null;
    }
};

let transporter;
setupEmailTransporter().then(t => transporter = t);

app.post("/api/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ message: "If a user with that email exists, a password reset OTP has been sent." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        await Otp.create({ email, otp });

        if (transporter) {
            const mailOptions = {
                from: '"MessageMaster Support" <support@messagemaster.com>',
                to: email,
                subject: "Your Password Reset OTP",
                text: `Your OTP for password reset is: ${otp}. It will expire in 10 minutes.`,
                html: `<p>Your OTP for password reset is: <strong>${otp}</strong>. It will expire in 10 minutes.</p>`,
            };
            await transporter.sendMail(mailOptions);
        } else {
            throw new Error("Email transporter is not ready.");
        }

        res.json({ message: "If a user with that email exists, a password reset OTP has been sent." });
    } catch (error) {
        console.error("Forgot password error:", error);
        res.status(500).json({ message: "Server error while sending OTP." });
    }
});

app.post("/api/reset-password", async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        const otpRecord = await Otp.findOne({ email, otp }).sort({ createdAt: -1 });

        if (!otpRecord) {
            return res.status(400).json({ message: "Invalid or expired OTP." });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        user.password = newPassword;
        await user.save();

        await Otp.deleteMany({ email });

        res.json({ message: "Password has been reset successfully." });
    } catch (error) {
        res.status(500).json({ message: "Server error while resetting password." });
    }
});


// ===================================================
// STORAGE MANAGEMENT API (ADMIN ONLY)
// ===================================================

// Helper function to recursively calculate the size of a directory
const getDirectorySize = (dirPath) => {
    let size = 0;
    try {
        const files = fs.readdirSync(dirPath);
        for (const file of files) {
            const filePath = path.join(dirPath, file);
            const stats = fs.statSync(filePath);
            if (stats.isFile()) {
                size += stats.size;
            } else if (stats.isDirectory()) {
                size += getDirectorySize(filePath);
            }
        }
    } catch (e) {
        // Ignore errors if directory doesn't exist
    }
    return size;
};

app.get('/api/admin/storage-usage', protect, adminOnly, async (req, res) => {
    try {
        // 1. Calculate File Storage Usage
        const uploadsPath = path.join(__dirname, 'uploads');
        const fileStorageBytes = getDirectorySize(uploadsPath);

        // 2. Calculate Database Storage Usage using a more reliable method
        const db = mongoose.connection.db;
        const dbStatsCommand = await db.command({ dbStats: 1 });
        const totalDbSizeBytes = dbStatsCommand.storageSize || 0;

        const collectionsData = await db.listCollections().toArray();
        const collectionNames = collectionsData.map(c => c.name);

        const collectionDetails = await Promise.all(
            collectionNames.map(async (name) => {
                const count = await db.collection(name).countDocuments();
                return {
                    name: name,
                    count: count
                };
            })
        );
        
        res.json({
            fileStorage: {
                bytes: fileStorageBytes,
                megabytes: (fileStorageBytes / (1024 * 1024)).toFixed(2)
            },
            databaseStorage: {
                bytes: totalDbSizeBytes,
                megabytes: (totalDbSizeBytes / (1024 * 1024)).toFixed(2),
                collections: collectionDetails
            }
        });

    } catch (error) {
        console.error("Storage usage calculation error:", error);
        res.status(500).json({ message: 'Server error calculating storage usage.' });
    }
});


// =================================================================
// --- SERVER STARTUP ---
// =================================================================
const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ role: "Admin" });
    if (!adminExists) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || "123456", salt);
      await User.create({ name: "Super Admin", email: process.env.ADMIN_EMAIL || "admin@example.com", password: hashedPassword, role: "Admin", status: "Active" });
      console.log("✅ Default Admin Created");
    }
  } catch (error) {
    console.error("❌ Error creating default admin:", error.message);
  }
};

const startServer = async () => {
  try {
    await connectDB();
    console.log("✅ MongoDB Connected");
    await createDefaultAdmin();
    const PORT = process.env.PORT || 5001;
    app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
