import { asyncHandler } from "../utils/asyncHandler.js";

const registerUser = asyncHandler( async (req,res) => {
    res.status(404).json({
        message: "Chai aur Code"
    })
})



export {registerUser}