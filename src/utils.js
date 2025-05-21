import bcrypt from "bcryptjs";
import JWT from "jsonwebtoken";

const REFRESH_SECRET = ";ozR:;v-t~KE2IAr^lCo`m@Fi#JOPpI1ueL8n1=m.hOS7BZf";
const ACCESS_SECRET = ";2!@uo^~ccvL81N3@ue-dvjU!d3*=Gje_7_,'&GSW%q.d&7pn7";

const ACCESS_TOKEN_EXPIRATION = 900;
const REFRESH_TOKEN_EXPIRATION = 2592000;

export const checkEmailFormat = (email) => {
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return re.test(email);
};

export const checkPasswordFormat = (password) => {
  const re = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
  return re.test(password);
};

export const hashPassword = async (password) => {
  try {
    const hash = await bcrypt.hash(password, 10);
    return hash;
  } catch (error) {
    console.error("Error hashing password:", error);
    return null;
  }
};

export const comparePassword = async (password, hash) => {
  if (!password || !hash) {
    return false;
  }

  try {
    const isMatch = await bcrypt.compare(password, hash);
    return isMatch;
  } catch (error) {
    console.error("Error comparing password:", error);
    return false;
  }
};

export const generateAccessToken = (payload) => {
  if (!payload) {
    return null;
  }

  try {
    const token = JWT.sign(payload, ACCESS_SECRET,
        {expiresIn: ACCESS_TOKEN_EXPIRATION});

    return token;
  } catch (error) {
    console.error("Error generating access token:", error);
    return null;
  }
};

export const generateRefreshToken = (payload) => {
  if (!payload) {
    return null;
  }

  try {
    const token = JWT.sign(payload, REFRESH_SECRET,
        {expiresIn: REFRESH_TOKEN_EXPIRATION});

    return token;
  } catch (error) {
    console.error("Error generating refresh token:", error);
    return null;
  }
};

export const verifyAccessToken = (token) => {
  try {
    const decoded = JWT.verify(token, ACCESS_SECRET);
    return decoded;
  } catch (error) {
    console.error("Error verifying access token:", error);
    return null;
  }
};

export const verifyRefreshToken = (token) => {
  try {
    const decoded = JWT.verify(token, REFRESH_SECRET);
    return decoded;
  } catch (error) {
    console.error("Error verifying refresh token:", error);
    return null;
  }
};
