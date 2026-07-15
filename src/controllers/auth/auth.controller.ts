import { loginSchema, registerSchema } from "./auth.schema"
import { Request,Response } from "express";
import { User } from "../../models/user.model";
import { hashPassword } from "../../lib/hash";
import jwt from 'jsonwebtoken';
import { sendEmail } from "../../lib/email";
import { checkPassword } from "../../lib/hash";
import { createAccessToken , createRefreshToken, verifyRefreshToken} from "../../lib/token";

function getAppURL(){
    return process.env.APP_URL || `http://localhost:${process.env.PORT}`
}
export async function registerHandler(req:Request,res:Response){
    try{
    const result=registerSchema.safeParse(req.body);

    if(!result.success){
        return res.status(400).json({
            message:'data is in wrong format',
            error :result.error.flatten
        })
    }

    const {name,email,password}=result.data;

    const normalizedEmail=email.toLowerCase().trim();
    const isUserPresent=await User.findOne({email: normalizedEmail});
    if(isUserPresent){
        return res.status(409).json({
            message : "User is already present with this email ! please try with a different email"
        });
    }
    const hashedPassword=await hashPassword(password);
    
    const newlyCreatedUser=await User.create({
        email:normalizedEmail,
        password: hashedPassword,
        role:'user',
        isEmailVerified:false,
        twoFactorEnabled:false
    })


    // email verification 
    const verifyToken=jwt.sign(
      {
        sub:newlyCreatedUser.id
      },
      process.env.JWT_ACCESS_SECRET!,
      {
        expiresIn : '1d'
      }
    )

    const verifyURL=`${getAppURL()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
        newlyCreatedUser.email,
        "Please verify email",
        `<p>please verify your email by clicking this link:</p>
         <p><a href="${verifyURL}">${verifyURL}</a></p>
        `
    )
return res.status(201).json({
    message: 'User Registered successfully',
    user:{
        id:newlyCreatedUser.id,
        email:newlyCreatedUser.email,
        role:newlyCreatedUser.role,
        isEmailVerified:newlyCreatedUser.isEmailVerified
    }
})
    }
    catch(err){
        console.log(err);
        res.status(500).json({
            message: 'internal server error'
    })
    }
}

export async function verifyEmailHandler(req:Request,res:Response){
    const token=req.query.token as string | undefined;

    if(!token){
        return res.status(400).json({message :"Verification token is missing"})
    }
   try{
    const payload=jwt.verify(token,process.env.JWT_ACCESS_SECRET!) as {
        sub: string;
    }
    const user=await User.findById(payload.sub);
    if(!user){
        return res.status(400).json({message :"User not found"})
    }

    if(user.isEmailVerified){
        return res.status(200).json({message:'user is already verified'});
    }
    user.isEmailVerified=true;
    await user.save();
    return res.status(200).json({message:'Email is verified successfully'});
   }
   catch(err){
    console.log(err);
    res.status(500).json({
        message: 'internal server error'
})
}
}

export async function LoginHandler(req:Request,res:Response){
    try{
        const result=loginSchema.safeParse(req.body);
        if(!result.success){
        return res.status(400).json({
            message:'data is in wrong format',
            error :result.error.flatten
        })
    } 
    
    const {email,password} =req.body;
    const normalEmail=email.toLowerCase().trim();

    const user=await User.findOne({email: normalEmail});
    if(!user){
        return res.status(409).json({
            message : "invalid email or password"
        });
    }
    const verifyPassword=await checkPassword(password,user.password);
    if(!verifyPassword){
        return res.status(400).json({message : 'invalid password'})
    }
 
    if(!user.isEmailVerified){
        return res.status(403).json({message : "Please verify your email before logging in"})
    }

    const accessToken=createAccessToken(user.id,user.role,user.tokenVersion);

    const refreshToken=createRefreshToken(user.id,user.tokenVersion);

    const isProd=process.env.NODE_ENV== "Production";

    res.cookie("refreshToken",refreshToken,{
           httpOnly:true,
           secure:isProd,
           sameSite:'lax',
           maxAge: 7*24*60*60*1000
    })

    return res.status(200).json({
        message:"Login successfully",
        accessToken,
        user:{
            id:user.id,
            email:user.email,
            role:user.role,
            isEmailVerified:user.isEmailVerified,
            twoFactorEnabled:user.twoFactorEnabled
        }
    })

    }
    catch(err){
        console.log(err);
        res.status(500).json({
            message: 'internal server error'
    })
    }
}

export async function refreshHandler(req:Request,res:Response){
    try {
        const token=req.cookies?.refreshToken as string | undefined;
        if(!token){
           return  res.status(401).json({message : "Refresh token missing"})
        }
        
        const payload=verifyRefreshToken(token);

        const user=await User.findById(payload.sub);

        if(!user){
            return res.status(401).json({message:"User not found"});
        }
 
        if(user.tokenVersion!=payload.tokenVersion){
            return res.status(401).json({message:"Refresh token invalidated"})
        }

        const newAccessToken=createAccessToken(user.id,user.role,user.tokenVersion);

        const newRefreshToken=createRefreshToken(user.id,user.tokenVersion);
        
        const isProd=process.env.NODE_ENV== "Production";

        res.cookie("refreshToken",newRefreshToken,{
               httpOnly:true,
               secure:isProd,
               sameSite:'lax',
               maxAge: 7*24*60*60*1000
        })
    
        return res.status(200).json({
            message:"Token Refreshed",
            accessToken:newAccessToken,
            user:{
                id:user.id,
                email:user.email,
                role:user.role,
                isEmailVerified:user.isEmailVerified,
                twoFactorEnabled:user.twoFactorEnabled
            }
        })

    } catch(err){
        console.log(err);
        res.status(500).json({
            message: 'internal server error'
    })
    }
}