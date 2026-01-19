const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { defineString } = require("firebase-functions/params");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

admin.initializeApp();

// Define parameters (set in .env file)
const gmailEmail = defineString("GMAIL_EMAIL");
const gmailPassword = defineString("GMAIL_PASSWORD");

// Configure Gmail transporter
const getTransporter = () => {
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: gmailEmail.value(),
      pass: gmailPassword.value(),
    },
  });
};

// Trigger when a new user document is created
exports.onNewUserSignup = onDocumentCreated("users/{userId}", async (event) => {
  const snap = event.data;
  if (!snap) {
    console.log("No data associated with the event");
    return;
  }

  const newUser = snap.data();
  const userId = event.params.userId;
  const adminEmail = gmailEmail.value();

  // Format the signup date
  const signupDate = newUser.signupDate
    ? newUser.signupDate.toDate().toLocaleString()
    : "Unknown";

  // Email content
  const mailOptions = {
    from: `CySA+ Exam Prep <${adminEmail}>`,
    to: adminEmail,
    subject: "New User Signup - CySA+ Exam Prep",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #2563eb;">New User Signup!</h2>
        <p>A new user has registered for CySA+ Exam Prep:</p>
        <table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd; background: #f5f5f5;"><strong>Email:</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">${newUser.email}</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd; background: #f5f5f5;"><strong>User ID:</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">${userId}</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd; background: #f5f5f5;"><strong>Signup Date:</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">${signupDate}</td>
          </tr>
        </table>
        <p style="color: #666;">
          <a href="https://cysa-exam-prep.web.app/admin.html" style="color: #2563eb;">View Admin Dashboard</a>
        </p>
      </div>
    `,
  };

  try {
    const transporter = getTransporter();
    await transporter.sendMail(mailOptions);
    console.log("New user notification email sent for:", newUser.email);
  } catch (error) {
    console.error("Error sending email:", error);
  }
});
