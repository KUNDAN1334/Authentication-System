import {Schema,model} from 'mongoose';
import { boolean, lowercase, trim } from 'zod';

const userSchema=new Schema({

    email:{
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase:true
   },

   password:{
    type: String,
    required: true
   },

   name:{
    type:String
   },

   isEmailVerified:{
    type:boolean,
    default:false
   },

   role:{
    type : String,
    enum:['user','admin'],
    default:"user"
   },

   twoFactorEnabled:{
    type:boolean,
    default:false
   },

   twoFactorSecret:{
    type : String,
    deafault:undefined
   },

   tokenVersion:{
    type:Number,
    default:0
   },

   resetPasswordToken:{
    type:String,
    default:undefined
   },

   resetPasswordExpires:{
    type: Date,
    default: undefined
   },

},{
    timestamps:true
})


export const    User=model('User',userSchema);