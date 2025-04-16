import userModel from "../models/userModel.js";


export const getAllUsers = async (req, res) => {
    try {
            const users = await userModel.find()
            return res.status(200).json({ success: true, data: users });
        } catch (error) {
            return res.json({success: false, message: error.message});
    }
}

export const getUserData = async (req, res) => {
    try {
        const{userId} = req.body;
        const user = await userModel.findById(userId);
        if(!user){
            return res.json({success: false, message: "User not found"});
        }
        return res.json({
            success: true, 
            userDate: {
                name: user.name,
                email: user.email,
                isAccountVerified: user.isAccountVerified
            }
        });
    } catch (error) {
        res.json({success: false, message: error.message});
    }
}



