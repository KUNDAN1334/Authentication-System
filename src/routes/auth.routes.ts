import { Router } from "express";
import { verifyEmailHandler,registerHandler,LoginHandler, refreshHandler } from "../controllers/auth/auth.controller";

const router=Router();

router.post("/register",registerHandler);
router.post("/login",LoginHandler);
router.get("/verify-email",verifyEmailHandler);
router.post("/refreshToken",refreshHandler);

export default router;