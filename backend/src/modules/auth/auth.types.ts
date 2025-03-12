export interface RegisterRequestBody {
  username: string;
  email: string;
  password: string;
}

export interface LoginRequestBody {
  email: string;
  password: string;
  token?: string;
  mfaType?: "Email" | "TOTP";
  emailOtpCode?: number;
}
export interface MFAMethods {
  TOTP?: boolean;
  Email?: boolean;
}
export interface ResetPasswordData {
  email: string; // User's email address
  token: string; // Reset token sent to the user
  newPassword: string; // New password chosen by the user
}
