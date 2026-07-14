import mongoose from "mongoose";
import { tr } from "zod/v4/locales";

export async function connectToDB(){
    try{
      await mongoose.connect(process.env.MONGO_URI!);
      console.log("MongoDB is connected")
    }
    catch(err){
      console.error("MongoDB Connection error!",err);
      process.exit(1);
    }
}