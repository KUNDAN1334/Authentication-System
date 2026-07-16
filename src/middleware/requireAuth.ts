import { Request, Response,NextFunction } from "express";
import { verifyAcessToken } from "../lib/token";
import { User } from "../models/user.model";

async function requireAuth(req: Request,res: Response,next: NextFunction){
    const authHeader=req.headers.authorization;

    if(!authHeader || !authHeader.startsWith("Bearer ")){
        return res.status(400).json({"message": "User is not authenticated"});
    }

    const token=authHeader.split(" ")[1];
    try {
        const payload=verifyAcessToken(token);
        
        const user=await User.findById(payload.sub);
        if(!user){
            return res.status(401).json({message:"User not found"})
        }

        if(user.tokenVersion!=payload.tokenVersion){
            return res.status(401).json({message : "Token invalidated"});
        }

        const authReq =req as any;
        authReq.user={

            id:user.id,
            email:user.email,
            name: user.name,
            isEmailVerified: user.isEmailVerified
        }

        next();
    } catch (error) {
        return res.status(401).json({message:"Invalid token"})
    }
}

export default requireAuth;