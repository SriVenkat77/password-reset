const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: 'https://password-reset-vg.netlify.app', // Adjust as needed
}));




// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date,
});

const User = mongoose.model('User', userSchema);

// Route to initiate password reset
app.post('/api/forgot-password', async (req, res) => {
  console.log('Forgot Password route hit'); // Add this line
  const { email } = req.body;
  const user = await User.findOne({ email });
  

  if (!user) {
    return res.status(404).json({ message: 'User not found Check the Credentials' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + 300000; // 5 min expiry
  await user.save();

  

  const resetLink = `https://password-reset-vg.netlify.app/reset-password/${token}`;
  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    to: user.email,
    from: process.env.EMAIL_USER,
    subject: 'Password Reset',
    text: `Please click on the following link, or paste this into your browser to reset your password:${resetLink}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error sending email:', err);  // Log the actual error
      console.log('User Email:', user.email);     
      
      return res.status(500).json({ message: 'Error sending email', error: err.message });
    }
    res.json({ message: 'Reset link sent to your email' });
  });
  
});

// Route to handle resetting the password
app.post('/api/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params; // Extract the token from the URL
    const { password } = req.body; // Extract the new password from the request body

    // Find the user with the matching reset token and check that the token hasn't expired
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() }, // Ensure the token is not expired
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired or Used token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the user's password and clear the reset token fields
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    // Save the user with the updated password
    await user.save();

    res.status(200).json({ message: 'Password reset successfull' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




app.listen(process.env.PORT || 5000, () => {
  console.log('Server is running on port 5000');
});
