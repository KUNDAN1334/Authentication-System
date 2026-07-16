import { Router } from "express";
import { verifyEmailHandler,registerHandler,LoginHandler, refreshHandler, logoutHandler, forgotPasswordHandler, resetPasswordHandler } from "../controllers/auth/auth.controller";

const router=Router();

router.post("/register",registerHandler);
router.post("/login",LoginHandler);
router.get("/verify-email",verifyEmailHandler);
router.post("/refreshToken",refreshHandler);
router.post("/logout",logoutHandler);
router.post("/forgot-password",forgotPasswordHandler);
router.post("/reset-password",resetPasswordHandler);

export default router;