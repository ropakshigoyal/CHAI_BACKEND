import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js";

export const verifyJWT = asyncHandler(async(req,resizeBy,next) => {
    try {
        const token =  req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")
    // ✅ It tries to get the token from cookie first.
    // 🔁 If not found, it tries to get it from the Authorization header.
    //  ✅ It stores the found value in a variable called token.
    if(!token)
    {
        throw new ApiError(401,"Unauthorized request")
    }
    
    const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    
    const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
    if(!user){
        throw new ApiError(401,"Invalid Access Token")
    }
    
    req.user = user;
    next()
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid access token")
    }

})