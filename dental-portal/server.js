import express from 'express';
import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'dental_portal_secret_key';

// Mock Database
const db = {
  referrals: new Map(),
};

// Email Transporter (Configure with your SMTP credentials or Resend/SendGrid)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: 2525,
  auth: {
    user: process.env.SMTP_USER || 'mock_user',
    pass: process.env.SMTP_PASS || 'mock_pass',
  },
});

// CREATE REFERRAL & SEND NOTIFICATION
app.post('/api/referrals', async (req, res) => {
  try {
    const { referringDoctorName, recipientEmail, patientId } = req.body;
    const referralId = `ref_${Date.now()}`;

    db.referrals.set(referralId, {
      referralId,
      recipientEmail,
      patientId,
      status: 'PENDING',
      createdAt: new Date().toISOString(),
    });

    // Build link with embedded redirect route
    const targetPath = encodeURIComponent(`/viewer.html?referralId=${referralId}`);
    const loginLink = `http://${req.get('host')}/login.html?redirectTo=${targetPath}`;

    await transporter.sendMail({
      from: '"Dental Practice Portal" <no-reply@yourportal.com>',
      to: recipientEmail,
      subject: `New Patient Referral from Dr. ${referringDoctorName}`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
          <h2 style="color: #0284c7;">New Referral Received</h2>
          <p>Dr. <strong>${referringDoctorName}</strong> has shared a 3D intraoral scan with you.</p>
          <p>Log in using <strong>${recipientEmail}</strong> to review the case details.</p>
          <br>
          <a href="${loginLink}" style="background-color: #0284c7; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
            Access Patient Case
          </a>
        </div>
      `,
    });

    return res.status(201).json({ message: 'Referral dispatched successfully.', referralId });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// AUTHENTICATION & LOGIN
app.post('/api/auth/login', (req, res) => {
  const { email, password, redirectTo } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required.' });
  }

  // Issue token
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '8h' });

  // Sanitize redirect target to prevent open redirect vulnerabilities
  const safeRedirect = redirectTo && redirectTo.startsWith('/') ? redirectTo : '/viewer.html';

  return res.json({ token, user: { email }, redirectTo: safeRedirect });
});

// AUTHENTICATED REFERRAL DATA FETCH
app.get('/api/referrals/:id', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unauthorized: Access token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired or invalid.' });

    const referral = db.referrals.get(req.params.id);
    if (!referral) return res.status(404).json({ error: 'Referral record not found.' });

    // Restrict access strictly to the recipient email address
    if (referral.recipientEmail.toLowerCase() !== user.email.toLowerCase()) {
      return res.status(403).json({ error: 'Access denied: You are not the assigned recipient for this referral.' });
    }

    return res.json(referral);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));