import * as nodemailer from "nodemailer";

interface EmailOptions {
  from: string;
  to: string;
  subject: string;
  text: string;
  html?: string;
}

// Function to send Email
async function sendEmail(options: EmailOptions): Promise<void> {
  try {
    const mailOptions = {
      from: options.from,
      to: options.to,
      subject: options.subject,
      text: options.text,
      html: options.html,
    };

    const transporter = nodemailer.createTransport({
      // host: "smtp.ethereal.email",
      host: "smtp.gmail.com",
      port: 587,
      secure: false, // or 'STARTTLS'
      auth: {
        user: process.env.USER_MAIL,
        pass: process.env.USER_PASS,
      },
    });

    const info = await transporter.sendMail(mailOptions);
    console.log(`Email sent: ${info.response}`);
  } catch (error) {
    console.error(error);
  }
}

// Function to send password reset email with OTP
async function sendPasswordResetEmailFunc(
  userEmail: string,
  link: string
): Promise<void> {
  const to = userEmail;
  const subject = "Password Reset Link";
  const text = `Your password reset Link is: ${link}`;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f0f4f8;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            max-width: 500px;
            width: 100%;
            background-color: #ffffff;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            border: 1px solid #e0e0e0;
        }
        .header {
            background-color: #28a745;
            color: white;
            padding: 15px;
            border-radius: 8px 8px 0 0;
            text-align: center;
            font-size: 24px;
            font-weight: bold;
        }
        .content {
            margin-top: 20px;
            text-align: center;
        }
        h2 {
            color: #333;
            font-size: 22px;
            margin-bottom: 20px;
        }
        p {
            color: #555;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .button {
            display: inline-block;
            background-color: #28a745;
            color: white;
            padding: 12px 25px;
            font-size: 18px;
            text-decoration: none;
            border-radius: 5px;
            transition: background-color 0.3s ease;
        }
        .button:hover {
            background-color: #218838;
        }
        .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #999;
            text-align: center;
        }
        @media (max-width: 600px) {
            .container {
                padding: 20px;
                width: 90%;
            }
            h2 {
                font-size: 20px;
            }
            p {
                font-size: 14px;
            }
            .button {
                font-size: 16px;
                padding: 10px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            Your Company Name
        </div>
        <div class="content">
            <h2>Password Reset Request</h2>
            <p>We received a request to reset your password.</p>
            <p>Click the button below to reset your password:</p>
            <a href="${link}" class="button">Reset Password</a>
            <p>If you did not request a password reset, no further action is required.</p>
        </div>
        <div class="footer">
            &copy; 2024 Your Company Name. All rights reserved.
        </div>
    </div>
</body>
</html>
`;

  await sendEmail({ from: "your-email@example.com", to, subject, text, html });
}

export { sendPasswordResetEmailFunc };
