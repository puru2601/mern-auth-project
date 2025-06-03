import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../model/userModel.js";
import transporter from "../config/nodemailer.js";

// User Register
export const register = async (req, res) => {
	const { name, email, password } = req.body;
	if (!name || !email || !password) {
		return res.json({ success: false, message: "Missing Details" });
	}
	try {
		const existingUser = await userModel.findOne({ email });
		if (existingUser) {
			return res.json({ success: false, message: "User already exists" });
		}
		const hashedPassword = await bcrypt.hash(password, 10);
		const user = new userModel({ name, email, password: hashedPassword });
		await user.save();

		const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
			expiresIn: "7d",
		});

		res.cookie("token", token, {
			httpOnly: true,
			secure: process.env.Node_ENV === "production",
			sameSite: process.env.Node_ENV === "production" ? "none" : "strict",
			maxAge: 7 * 24 * 60 * 60 * 1000,
		});

		const mailOptions = {
			from: process.env.EMAIL_ADDRESS,
			to: email,
			subject: "Welcome to mern_auth",
			text: `Welcome to authentication website. Your account has been created with email id: ${email}`,
		};

		await transporter.sendMail(mailOptions);

		return res.json({ success: true });
	} catch (error) {
		res.json({ success: false, message: error.message });
	}
};

// User Login
export const login = async (req, res) => {
	const { email, password } = req.body;
	if (!email || !password) {
		return res.json({
			success: false,
			message: "Email and password are required",
		});
	}
	try {
		const user = await userModel.findOne({ email });
		if (!user) {
			return res.json({ success: false, messaage: "Invalid email" });
		}

		const isMatch = await bcrypt.compare(password, user.password);

		if (!isMatch) {
			return res.json({ success: false, messaage: "Invalid password" });
		}
		const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
			expiresIn: "7d",
		});

		res.cookie("token", token, {
			httpOnly: true,
			secure: process.env.Node_ENV === "production",
			sameSite: process.env.Node_ENV === "production" ? "none" : "strict",
			maxAge: 7 * 24 * 60 * 60 * 1000,
		});

		return res.json({ success: true });
	} catch (error) {
		return res.json({ success: false, message: error.message });
	}
};

// User Logout
export const logout = async (req, res) => {
	try {
		res.clearCookie("token", {
			httpOnly: true,
			secure: process.env.Node_ENV === "production",
			sameSite: process.env.Node_ENV === "production" ? "none" : "strict",
		});
		return res.json({ success: true, message: "Logged Out" });
	} catch (error) {
		return res.json({ success: false, message: error.message });
	}
};

// sending email verification otp to the user's Email
export const sendVerifyOtp = async (req, res) => {
	try {
		const userId = req.user?.id;

		if (!userId) {
			return res.status(401).json({ success: false, message: "Unauthorized" });
		}

		const user = await userModel.findById(userId);

		if (!user) {
			return res
				.status(404)
				.json({ success: false, message: "User not found" });
		}

		if (user.isAccountVerified) {
			return res.json({ success: false, message: "Account already verified" });
		}

		// Generate 6-digit OTP
		const otp = String(Math.floor(100000 + Math.random() * 900000));

		user.verifyOtp = otp;
		user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours from now

		await user.save();

		const mailOptions = {
			from: process.env.EMAIL_ADDRESS,
			to: user.email,
			subject: "Account Verification OTP",
			text: `Your email verification code is ${otp}. Verify your account using this OTP.`,
		};

		await transporter.sendMail(mailOptions);

		res.json({
			success: true,
			message: "Verification code sent to your email",
		});
	} catch (error) {
		res.status(500).json({ success: false, message: error.message });
	}
};

// verifing email using the sent OTP
export const verifyEmail = async (req, res) => {
	const userId = req.user?.id;
	const { otp } = req.body;

	if (!userId || !otp) {
		return res.status(400).json({ success: false, message: "Missing details" });
	}

	try {
		const user = await userModel.findById(userId);

		if (!user) {
			return res
				.status(404)
				.json({ success: false, message: "User not found" });
		}

		if (!user.verifyOtp || user.verifyOtp !== otp) {
			return res.status(400).json({ success: false, message: "Invalid OTP" });
		}

		if (user.verifyOtpExpireAt < Date.now()) {
			return res.status(400).json({ success: false, message: "OTP expired" });
		}

		user.isAccountVerified = true;
		user.verifyOtp = "";
		user.verifyOtpExpireAt = 0;

		await user.save();

		return res.json({ success: true, message: "Email verified successfully" });
	} catch (error) {
		return res.status(500).json({ success: false, message: error.message });
	}
};

// check if user is Authenticated
export const isAuthenticated = async (req, res) => {
	try {
		return res.json({ success: true });
	} catch (error) {
		res.json({ success: false, message: error.message });
	}
};

// Sending Password Reset OTP
export const sendResetOtp = async (req, res) => {
	const { email } = req.body;

	if (!email) {
		return res.json({ success: false, message: "Email is required" });
	}

	try {
		const user = await userModel.findOne({ email });
		if (!user) {
			return res.json({ success: false, message: "User not found" });
		}

		// Generate 6-digit OTP
		const otp = String(Math.floor(100000 + Math.random() * 900000));

		user.resetOtp = otp;
		user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // 24 hours from now

		await user.save();

		const mailOptions = {
			from: process.env.EMAIL_ADDRESS,
			to: user.email,
			subject: "Reset Password OTP",
			text: `Your password reset code is ${otp}. use this to change your password.`,
		};

		await transporter.sendMail(mailOptions);

		return res.json({
			success: true,
			message: "Verification code sent to your email",
		});
	} catch (error) {
		return res.json({ success: false, message: error.message });
	}
};

// Reset otp password
export const resetPassword = async (req, res) => {
	const { email, otp, newPassword } = req.body;

	if (!email || !otp || !newPassword) {
		return res.json({
			success: false,
			message: "Email, OTP, and new password are required",
		});
	}
	try {
		const user = await userModel.findOne({ email });
		if (!user) {
			return res.json({ success: false, message: "User not found" });
		}
		if (user.resetOtp === "" || user.resetOtp !== otp) {
			return res.json({ success: false, message: "Invalid OTP" });
		}
		if (user.resetOtpExpireAt < Date.now()) {
			return res.json({ success: false, message: "OTP Expired" });
		}
		const hashedPassword = await bcrypt.hash(newPassword, 10);

		user.password = hashedPassword;
		user.resetOtp = "";
		user.resetOtpExpireAt = 0;

		await user.save();

		return res.json({
			success: true,
			message: "Password has been reset successfully",
		});
	} catch (error) {
		return res.json({ success: false, message: error.message });
	}
};
