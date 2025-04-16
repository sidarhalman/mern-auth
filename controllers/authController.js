import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';


export const register = async (req, res) => { 
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json(400).json({success: false, message: "All fields are required"});
    }
    try {
        const existingUser = await userModel.findOne({email})
        if (existingUser) {
            return res.json({success: false, message: "User already exists"});
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await userModel.create({name, email, password: hashedPassword});
        await user.save();

        const token = jwt.sign({email: user.email, id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Account Verification',
            text: `Your account has been created with email id: ${email}`
        }
        await transporter.sendMail(mailOptions);

        return res.json({success: true, message: "User created"});
    } catch (error) {
        res.json({success: false, message: error.message});
    }

}
export const login = async (req, res) => {
    const {email, password} = req.body;
    if (!email || !password) {
        return res.json({success: false, message: "All fields are required"});
    }
    try {
        const user = await userModel.findOne({email});
        if (!user) {
            return res.json({success: false, message: "Invalid credentials"});
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({success: false, message: "Invalid credentials"});
        }
        const token = jwt.sign({email: user.email, id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        return res.json({success: true, message: "Logged in"});
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });
        return res.json({success: true, message: "Logged out"});
        
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}

export const verifyOtp = async (req, res) => {
    try {

        const{userId} = req.body;
        const user = await userModel.findById(userId);
        if (user.isverified) {
            return res.json({success: false, message: "User is already verified"});
        }

        const otp =`${Math.floor(100000 + Math.random() * 900000)}`;
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verificatio OTP',
            text: `Your OTP is ${otp}. Verify your account using this OTP`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success: true, message: "OTP sent"});

    } catch (error) {
        res.json({success: false, message: error.message});
    }
}
export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;
    if(!userId || !otp) {
        return res.json({success: false, message: "All fields are required"});
    }
    try {
        const user = await userModel.findById(userId);
        if(!user){
            return res.json({success: false, message: "User not found"});
        }
        if(user.verifyOtp === "" || user.verifyOtp !== otp){
            return res.json({success: false, message: "Invalid OTP"});
        }
        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success: false, message: "OTP expired"});
        }
        user.isAccountVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpireAt = 0;
        await user.save();
        return res.json({success: true, message: "Email verified"});
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}

export const isAuthenticaded = async (req, res) => {
    try {
        return res.json({success: true, message: "Authenticated"});
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}

export const sendResetOtp = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.json({success: false, message: "Email is required"});
    }
    try {
        const user = await userModel.findOne({
            email
        });
        if (!user) {
            return res.json({success: false, message: "User not found"});
        }
        const otp = `${Math.floor(100000 + Math.random() * 900000)}`;
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 10 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Reset Password OTP',
            text: `Your OTP is ${otp}. Reset your password using this OTP`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success: true, message: "OTP sent"});
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}

export const resetPassword = async (req, res) => {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password) {
        return res.json({success: false, message: "All fields are required"});
    }
    try {
        const user = await userModel.findOne({
            email
        });
        if (!user) {
            return res.json({success: false, message: "User not found"});
        }
        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({success: false, message: "Invalid OTP"});
        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({success: false, message: "OTP expired"});
        }
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        user.password = await bcrypt.hash(password, 10);
        await user.save();
        return res.json({success: true, message: "Password reset successful"});
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}


/*
export const login = async (req, res) => {
    const {email, password} = req.body
    if(!email || !password){
        return res.json({success:false, message: "All field are required"})
    }
    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({success:false, message:"User is not exist"})
        }
        const isPasswordMatch = await bcrypt.compare(password, user.password)
        if(!isPasswordMatch){
            return res.json({success:false, message:"Invalid credentials"})
        }
        return res.status(200).json({success:true, message:"User logged in!!"})
        
    } catch (error) {
            res.json({
                success:false, 
                message:error.message
            })
    }
}
*/