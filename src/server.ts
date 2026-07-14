import http from 'http';
import dotenv from 'dotenv';
import { connectToDB } from './config/db';
import app from './app';

dotenv.config();

async function startServer(){
    await connectToDB();
    const server=http.createServer(app);
    server.listen(process.env.PORT,()=>{
        console.log(`server is now running at ${process.env.PORT}`);
    })
}


startServer().catch((err)=>{
    console.error("error while starting the server",err);
    process.exit(1);
})