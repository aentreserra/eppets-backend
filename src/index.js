import {onCall} from "firebase-functions/v2/https";
import {onSchedule} from "firebase-functions/v2/scheduler";
import {createClient} from "@libsql/client";
import admin from "firebase-admin";
import {
  comparePassword,
  generateAccessToken,
  generateRefreshToken,
  hashPassword,
  verifyAccessToken,
  verifyRefreshToken,
} from "./utils.js";
import pkg from "rrule";
const {RRule, rrulestr} = pkg;
import sgMail from "@sendgrid/mail";

admin.initializeApp();

// Requiere las credenciales de la base de datos
const db = createClient({
  url: "url_base_de_datos",
  authToken: "token_de_acceso",
});

const storage = admin.storage();
const bucket = storage.bucket();

// Requiere el token de correo
sgMail.setApiKey("token");

/* const ACCESS_TOKEN_EXPIRATION = 900;
const REFRESH_TOKEN_EXPIRATION = 2592000;*/
const MIN_XP_TO_CREATE_EVENT = 100;

/**
 * Función para crear un nuevo usuario
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * contiene el accessToken y refreshToken.
 */
export const createUserAttempt = onCall(async (request) => {
  const {name, email, password, fcm} = request.data;

  if (!name || !email || !password) {
    return {success: false, message: "Missing required fields"};
  }

  const normalizedEmail = email.toLowerCase();

  const userExists = await db.execute(
      "SELECT email FROM users WHERE email = ?", [normalizedEmail],
  );

  if (userExists.rows.length > 0) {
    return {success: false, message: "User already exists"};
  }

  const hashedPassword = await hashPassword(password);

  if (!hashedPassword) {
    return {success: false, message: "Error hashing password"};
  }

  const jti = Math.random().toString(36).substring(2, 15);

  const result = await db.execute(
      "INSERT INTO users (name, email, password_hash, jti) VALUES (?, ?, ?, ?)",
      [name, normalizedEmail, hashedPassword, jti],
  );

  if (result.rowsAffected === 0) {
    return {success: false, message: "Error creating user"};
  }

  const userId = result.lastInsertRowid.toString();

  const fcmInsertResult = await db.execute(
      "INSERT INTO fcm_tokens (user_id, fcm_token, platform)" +
      "VALUES (?, ?, 'android')",
      [userId, fcm],
  );

  if (fcmInsertResult.rowsAffected === 0) {
    return {success: false, message: "Error inserting FCM token"};
  }

  const refreshToken = generateRefreshToken({sub: userId, jti});
  const accessToken = generateAccessToken({sub: userId});

  return {success: true, accessToken, refreshToken};
});

/**
 * Función para iniciar sesión de un usuario
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * contiene el accessToken, refreshToken y nombre del usuario.
 */
export const loginUserAttempt = onCall(async (request) => {
  const {email, password, fcm} = request.data;

  if (!email || !password) {
    return {success: false, message: "Missing required fields"};
  }

  const normalizedEmail = email.toLowerCase();

  const sql = `
    SELECT email, password_hash, name, jti, id, xp
    FROM users WHERE email = ?
  `;

  const user = await db.execute({
    sql: sql,
    args: [normalizedEmail],
  });

  if (user.rows.length === 0) {
    return {success: false, message: "User not found"};
  }

  const userData = user.rows[0];

  const passwordMatch = await comparePassword(password, userData.password_hash);

  if (!passwordMatch) {
    return {success: false, message: "Invalid password"};
  }

  try {
    await db.execute(
        "INSERT INTO fcm_tokens (user_id, fcm_token, platform)" +
        "VALUES (?, ?, 'android')",
        [userData.id, fcm],
    );
  } catch (error) {
    console.error("Error on token insert:", error);
  }

  const refreshToken = generateRefreshToken({
    sub: userData.id,
    jti: userData.jti,
  });
  const accessToken = generateAccessToken({sub: userData.id});

  return {
    success: true,
    name: userData.name,
    userXp: userData.xp,
    accessToken,
    refreshToken,
  };
});

/**
 * Función para enviar un código al correo y guardarlo en la base de datos
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const forgotPasswordSendCode = onCall(async (request) => {
  const {email} = request.data;

  if (!email) {
    return {success: false, message: "Missing required fields"};
  }

  const normalizedEmail = email.toLowerCase();

  const sql = `
    SELECT email FROM users WHERE email = ?
  `;

  const user = await db.execute({
    sql: sql,
    args: [normalizedEmail],
  });

  if (user.rows.length === 0) {
    return {success: false, message: "User not found"};
  }

  let code = "";

  for (let i = 0; i < 6; i++) {
    code += Math.floor(Math.random() * 10).toString();
  }

  const sql2 = `
    INSERT INTO recovery_password_codes (email, code) VALUES (?, ?)
  `;

  await db.execute({
    sql: sql2,
    args: [normalizedEmail, code],
  });

  const msg = {
    to: email,
    from: "eppetsmail@gmail.com",
    subject: "Eppets - Código de recuperación de contraseña",
    html: "<strong>Hola,</strong> tu codigo de recuperación es " + code,
  };

  try {
    await sgMail.send(msg);
  } catch (error) {
    console.error("Error sending email:", error);
    return {success: false, message: "Error sending email"};
  }

  return {success: true};
});

/**
 * Función para verificar el código y enviar un access_token temporal
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa
 * y el access_token
 */
export const verifyRecoveryCode = onCall(async (request) => {
  const {email, code} = request.data;

  if (!email || !code) {
    return {success: false, message: "Missing required fields"};
  }

  const normalizedEmail = email.toLowerCase();

  const sql = `
    SELECT created_at FROM recovery_password_codes
    WHERE email = ? AND code = ?
  `;

  const result = await db.execute({
    sql: sql,
    args: [normalizedEmail, code],
  });

  if (result.rows.length === 0) {
    return {success: false, message: "Invalid code"};
  }

  const createdAt = new Date(result.rows[0].created_at);
  const now = new Date();

  const expirationTime = 15 * 60 * 1000; // 15 minutos
  if (now - createdAt > expirationTime) {
    return {success: false, message: "Code expired"};
  }

  const accessToken = generateAccessToken({sub: normalizedEmail});

  return {success: true, accessToken};
});

/**
 * Función para guardar la nueva contraseña
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const resetPasswordAttempt = onCall(async (request) => {
  const {accessToken, newPassword} = request.data;

  if (!accessToken || !newPassword) {
    return {success: false, message: "Missing required fields"};
  }
  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid access token"};
  }

  const email = decodedToken.sub; // El sub es el email

  const hashedPassword = await hashPassword(newPassword);

  if (!hashedPassword) {
    return {success: false, message: "Error hashing password"};
  }

  const sql2 = `
    UPDATE users SET password_hash = ? WHERE email = ?
  `;

  await db.execute({
    sql: sql2,
    args: [hashedPassword, email],
  });

  return {success: true};
});

/**
 * Función para cerrar sesión de un usuario eliminando el token FCM
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const logoutUserAttempt = onCall(async (request) => {
  const {accessToken, fcm} = request.data;

  if (!accessToken || !fcm) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid access token"};
  }

  const userId = decodedToken.sub;

  const result = await db.execute(
      "DELETE FROM fcm_tokens WHERE user_id = ? AND fcm_token = ?",
      [userId, fcm],
  );

  if (result.rowsAffected === 0) {
    return {success: false, message: "Error deleting FCM token"};
  }

  return {success: true};
});

/**
 * Función para verificar el token de acceso
 * @param {Object} request - El objeto de solicitud que contiene el token
 * de acceso.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa
 * y contiene un nuevo refreshToken y accessToken.
 */
export const refreshTokenAttempt = onCall(async (request) => {
  const {refreshToken} = request.data;

  if (!refreshToken) {
    return {success: false, message: "Missing refresh token"};
  }

  const decoded = verifyRefreshToken(refreshToken);

  if (!decoded) {
    return {success: false, message: "Invalid refresh token"};
  }

  const userId = decoded.sub;
  const jti = decoded.jti;

  const user = await db.execute(
      "SELECT id FROM users WHERE id = ? AND jti = ?",
      [userId, jti],
  );

  if (user.rows.length === 0) {
    return {success: false, message: "User not found"};
  }

  const newRefreshToken = generateRefreshToken({sub: userId, jti});
  const newAccessToken = generateAccessToken({sub: userId});

  return {
    success: true,
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
  };
});

/**
 * Función para eliminar un usuario
 * @param {Object} request - El objeto de solicitud que contiene el token
 * de acceso.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const deleteUser = onCall(async (request) => {
  const {accessToken} = request.data;

  if (!accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      DELETE FROM users WHERE id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [userId],
    });

    const isDeleted = result.rowsAffected > 0;
    if (!isDeleted) {
      return {success: false, message: "Error deleting user"};
    }

    return {success: true};
  } catch (error) {
    console.error("Error deleting user:", error);
    return {success: false, message: "Error deleting user"};
  }
});

/**
 * Función para cambiar la contraseña de un usuario
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const changePassword = onCall(async (request) => {
  const {accessToken, oldPassword, newPassword} = request.data;

  if (!accessToken || !newPassword || !oldPassword) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      SELECT password_hash FROM users WHERE id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [userId],
    });

    if (result.rows.length === 0) {
      return {success: false, message: "User not found"};
    }

    const userData = result.rows[0];
    const passwordMatch = await comparePassword(
        oldPassword,
        userData.password_hash,
    );

    if (!passwordMatch) {
      return {success: false, message: "Invalid password"};
    }

    const hashedPassword = await hashPassword(newPassword);
    if (!hashedPassword) {
      return {success: false, message: "Error hashing password"};
    }

    const jti = Math.random().toString(36).substring(2, 15);

    const sql2 = `
      UPDATE users SET password_hash = ?, jti = ? WHERE id = ?
    `;

    const result2 = await db.execute({
      sql: sql2,
      args: [hashedPassword, jti, userId],
    });

    const isUpdated = result2.rowsAffected > 0;

    if (!isUpdated) {
      return {success: false, message: "Error updating password"};
    }

    const refreshToken = generateRefreshToken({sub: userId, jti});

    return {success: true, refreshToken};
  } catch (error) {
    console.error("Error updating password:", error);
    return {success: false, message: "Error updating password"};
  }
});

/**
 * Función para generar una URL de carga firmada
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * de la carga.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * contiene la URL firmada.
 */
export const generateUploadUrl = onCall(async (request) => {
  const {filename, contentType, accessToken} = request.data;

  if (!filename || !contentType || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);
  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }
  const userId = decodedToken.sub;

  const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
  const filePath = `user-uploads/${userId}/${Date.now()}-${safeFilename}`;
  const file = bucket.file(filePath);

  const options = {
    version: "v4",
    action: "write",
    expires: Date.now() + 15 * 60 * 1000, // 15 minutos validez
    contentType: contentType,
  };

  try {
    const [signedUrl] = await file.getSignedUrl(options);

    return {
      success: true,
      signedUrl,
      filePath,
    };
  } catch (error) {
    console.error("Error generating signed URL:", error);
    return {success: false, message: "Error generating signed URL"};
  }
});

/**
 * Función para crear un nuevo perfil de mascota
 * @param {Object} request - El objeto de solicitud que contiene la información
 * de la mascota.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const createNewPetProfile = onCall(async (request) => {
  const {
    name,
    species,
    breed,
    bornDate,
    gender,
    color,
    microchip,
    neutered,
    weight,
    imageUrl,
    accessToken,
  } = request.data;

  if (!name || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
    INSERT INTO pet_profiles (
      name, species, breed, born_date, gender,
      color, microchip, neutered, weight, image_url, user_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

    const result = await db.execute({
      sql: sql,
      args: [
        name,
        species !== undefined ? species : null,
        breed !== undefined ? breed : null,
        bornDate !== undefined ? bornDate : null,
        gender !== undefined ? gender : null,
        color !== undefined ? color : null,
        microchip !== undefined ? microchip : null,
        neutered !== undefined ? neutered : null,
        weight !== undefined ? weight : null,
        imageUrl !== undefined ? imageUrl : null,
        userId,
      ],
    });

    if (result.rowsAffected === 0) {
      return {success: false, message: "Error creating pet profile"};
    }

    const petProfileId = result.lastInsertRowid.toString();

    try {
      await giveUserXp(userId, 23);
    } catch (error) {
      console.error("Error giving XP to user:", error);
    }

    return {success: true, petProfileId, xp: 23};
  } catch (error) {
    console.error("Error inserting pet profile:", error);
    return {success: false, message: "Error inserting pet profile"};
  }
});

/**
 * Función para obtener el perfil de una mascota en concreto
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * los datos de la mascota.
 */
export const getPetProfile = onCall(async (request) => {
  const {petId, accessToken} = request.data;

  if (!petId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      SELECT * FROM pet_profiles WHERE id = ? AND user_id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [petId, userId],
    });

    const petProfile = result.rows[0];

    if (!petProfile) {
      return {success: false, message: "Pet profile not found"};
    }

    const sql2 = `
      SELECT * FROM medical_records WHERE pet_id = ?
    `;

    const result2 = await db.execute({
      sql: sql2,
      args: [petId],
    });

    const medicalRecords = result2.rows;

    return {success: true, petProfile, medicalRecords};
  } catch (error) {
    console.error("Error fetching pet profile:", error);
    return {success: false, message: "Error fetching pet profile"};
  }
});

/**
 * Función para obtener todas las mascotas de un usuario
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * los datos de las mascotas.
 */
export const getPetsFromUser = onCall(async (request) => {
  const {accessToken} = request.data;

  if (!accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid access token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = "SELECT * FROM pet_profiles WHERE user_id = ?";
    const result = await db.execute({
      sql: sql,
      args: [userId],
    });

    const pets = result.rows;

    if (pets.length === 0) {
      return {success: false, message: "No pets found"};
    }

    return {success: true, pets};
  } catch (error) {
    console.error("Error fetching pets:", error);
    return {success: false, message: "Error fetching pets"};
  }
});

/**
 * Función para actualizar el peso de la mascota
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y mascota.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const updatePetWeight = onCall(async (request) => {
  const {petId, newWeight, date, accessToken} = request.data;

  if (!accessToken || !petId || !newWeight) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `UPDATE pet_profiles SET weight = ?
      WHERE id = ? AND user_id = ?`;
    const result = await db.execute({
      sql: sql,
      args: [newWeight, petId, userId],
    });

    const isUpdated = result.rowsAffected > 0;

    if (!isUpdated) {
      return {success: false, message: "Error updating pet weight"};
    }
    const sql2 = `INSERT INTO pet_weights (pet_id, weight_value, date_recorded)
      VALUES (?, ?, ?)`;

    const result2 = await db.execute({
      sql: sql2,
      args: [petId, newWeight, date],
    });

    const isInserted = result2.rowsAffected > 0;

    if (!isInserted) {
      return {success: false, message: "Error inserting weight history"};
    }

    try {
      await giveUserXp(userId, 5);
    } catch (error) {
      console.error("Error giving XP to user:", error);
    }

    return {success: true, xp: 5};
  } catch (error) {
    console.error("Error weighting pet:", error);
    return {success: false, message: "Error weighting pet"};
  }
});

/**
 * Función para actualizar el perfil de una mascota
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y mascota.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const updatePetProfile = onCall(async (request) => {
  const {
    id,
    name,
    species,
    breed,
    bornDate,
    gender,
    color,
    microchip,
    neutered,
    weight,
    imageUrl,
    accessToken,
  } = request.data;

  if (!name || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      UPDATE pet_profiles
      SET name = ?, species = ?, breed = ?, born_date = ?,
      gender = ?, color = ?, microchip = ?, neutered = ?, weight = ?,
      image_url = ?
      WHERE user_id = ? AND id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [
        name,
        species !== undefined ? species : null,
        breed !== undefined ? breed : null,
        bornDate !== undefined ? bornDate : null,
        gender !== undefined ? gender : null,
        color !== undefined ? color : null,
        microchip !== undefined ? microchip : null,
        neutered !== undefined ? neutered : null,
        weight !== undefined ? weight : null,
        imageUrl !== undefined ? imageUrl : null,
        userId,
        id,
      ],
    });

    const isUpdated = result.rowsAffected > 0;
    if (!isUpdated) {
      return {success: false, message: "Error updating pet profile"};
    }

    return {success: true};
  } catch (error) {
    console.error("Error updating pet profile:", error);
    return {success: false, message: "Error updating pet profile"};
  }
});

/**
 * Función para eliminar el perfil de una mascota
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y mascota.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const deletePetProfile = onCall(async (request) => {
  const {petId, accessToken} = request.data;

  if (!petId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      DELETE FROM pet_profiles
      WHERE id = ? AND user_id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [petId, userId],
    });

    const isDeleted = result.rowsAffected > 0;
    if (!isDeleted) {
      return {success: false, message: "Error deleting pet profile"};
    }

    return {success: true};
  } catch (error) {
    console.error("Error deleting pet profile:", error);
    return {success: false, message: "Error deleting pet profile"};
  }
});

/**
 * Función para obtener los datos del usuario, novedades y mascotas
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * datos.
 */
export const getData = onCall(async (request) => {
  const {accessToken} = request.data;

  if (!accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      SELECT title, icon, created_at
      FROM app_news
      ORDER BY created_at ASC
      LIMIT 10;
    `;
    const resultAppNews = await db.execute({
      sql: sql,
      args: [],
    });

    const news = resultAppNews.rows;

    const sql2 = `
      SELECT id, pet_id, title, body, reminder_type, trigger_datetime_utc,
      recurrence_rule, next_trigger_datetime_utc, is_active, created_at
      FROM reminders
      WHERE user_id = ? AND
      next_trigger_datetime_utc >= datetime('now', '-5 days') AND
      next_trigger_datetime_utc <= datetime('now', '+2 months')
    `;

    const resultUserNews = await db.execute({
      sql: sql2,
      args: [userId],
    });

    const reminders = resultUserNews.rows;

    return {success: true, news, reminders};
  } catch (error) {
    console.error("Error fetching pets:", error);
    return {success: false, message: "Error fetching pets"};
  }
});

/**
 * Función para añadir un recordatorio
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y recordatorio.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y id.
 */
export const addReminder = onCall(async (request) => {
  const {
    petId,
    title,
    body,
    reminderType,
    triggerDatetimeUtc,
    recurrenceRule,
    instructions,
    accessToken,
  } = request.data;

  if (!petId || !title || !reminderType || !triggerDatetimeUtc ||
    !recurrenceRule || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  const nextTriggerDatetimeUtc = triggerDatetimeUtc;

  try {
    const sql = `
      INSERT INTO reminders (
        pet_id, user_id, title, body, reminder_type,
        trigger_datetime_utc, next_trigger_datetime_utc, recurrence_rule,
        is_active, instructions
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const result = await db.execute({
      sql: sql,
      args: [
        petId,
        userId,
        title,
        body,
        reminderType,
        triggerDatetimeUtc,
        nextTriggerDatetimeUtc,
        recurrenceRule,
        true,
        instructions !== undefined ? instructions : null,
      ],
    });

    if (result.rowsAffected === 0) {
      return {success: false, message: "Error creating reminder"};
    }

    try {
      await giveUserXp(userId, 15);
    } catch (error) {
      console.error("Error giving XP to user:", error);
    }

    return {
      success: true,
      reminderId: result.lastInsertRowid.toString(),
      xp: 15,
    };
  } catch (error) {
    console.error("Error creating reminder:", error);
    return {success: false, message: "Error creating reminder"};
  }
});

/**
 * Función para borrar un recordatorio
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y recordatorio.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const deleteReminder = onCall(async (request) => {
  const {reminderId, accessToken} = request.data;

  if (!reminderId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      DELETE FROM reminders
      WHERE id = ? AND user_id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [reminderId, userId],
    });

    const isDeleted = result.rowsAffected > 0;
    if (!isDeleted) {
      return {success: false, message: "Error deleting reminder"};
    }

    return {success: true};
  } catch (error) {
    console.error("Error deleting reminder:", error);
    return {success: false, message: "Error deleting reminder"};
  }
});

/**
 * Función para añadir un evento de la comunidad
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y evento.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * evento.
 */
export const addCommunityEvent = onCall(async (request) => {
  const {
    title,
    description,
    body,
    notes,
    latitude,
    longitude,
    eventDatetime,
    maxAttendees,
    iconName,
    address,
    accessToken,
  } = request.data;

  if (!title || !description || !latitude ||
    !longitude || !eventDatetime || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const userXpLevel = await getUserXpLevel(userId);

    if (!userXpLevel) {
      return {success: false, message: "User not found"};
    }
    const userXp = userXpLevel.xp;

    if (userXp < MIN_XP_TO_CREATE_EVENT) {
      return {
        success: false,
        message: "Not enough XP",
      };
    }
    const sql = `
      INSERT INTO community_events (
        title, description, body, notes, latitude, longitude,
        event_datetime_utc, max_attendees, icon_name, address, creator_user_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const eventDatetimeUtc = new Date(eventDatetime).toISOString();

    const result = await db.execute({
      sql: sql,
      args: [
        title,
        description,
        body !== undefined ? body : null,
        notes !== undefined ? notes : null,
        latitude,
        longitude,
        eventDatetimeUtc,
        maxAttendees !== undefined && maxAttendees !== null &&
          !isNaN(parseInt(maxAttendees)) ? parseInt(maxAttendees) : null,
        iconName !== undefined ? iconName : "dog",
        address !== undefined ? address : "No especificado",
        userId,
      ],
    });

    if (result.rowsAffected === 0) {
      return {success: false, message: "Error creating event"};
    }

    try {
      await giveUserXp(userId, 30);
    } catch (error) {
      console.error("Error giving XP to user:", error);
    }

    return {success: true, eventId: result.lastInsertRowid.toString(), xp: 30};
  } catch (error) {
    console.error("Error creating event:", error);
    return {success: false, message: "Error creating event"};
  }
});

/**
 * Función para eliminar un evento de la comunidad
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y evento.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const deleteCommunityEvent = onCall(async (request) => {
  const {eventId, accessToken} = request.data;

  if (!eventId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      DELETE FROM community_events
      WHERE id = ? AND creator_user_id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [eventId, userId],
    });

    const isDeleted = result.rowsAffected > 0;
    if (!isDeleted) {
      return {success: false, message: "Event not found or not owned by user"};
    }

    return {success: true};
  } catch (error) {
    console.error("Error deleting event:", error);
    return {success: false, message: "Error deleting event"};
  }
});

/**
 * Función para obtener los evetos creados por el usuario
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * datos.
 */
export const getOwnedCommunityEvents = onCall(async (request) => {
  const {accessToken} = request.data;

  if (!accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      SELECT id, title, description, body, notes, latitude, longitude,
      event_datetime_utc, max_attendees, is_active, icon_name, address
      FROM community_events
      WHERE creator_user_id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [userId],
    });

    const events = result.rows;

    return {success: true, events};
  } catch (error) {
    console.error("Error fetching events:", error);
    return {success: false, message: "Error fetching events"};
  }
});

/**
 * Función para obtener los eventos de comunidad filtrados por distancia
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * datos.
 */
export const getCommunityEvents = onCall(async (request) => {
  const {latitude, longitude, accessToken} = request.data;

  if (!accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  if (!userId) {
    return {success: false, message: "Invalid token"};
  }

  if (!latitude || !longitude) {
    return {success: false, message: "Missing required fields"};
  }

  try {
    // Usamos el calculo de Bounding Box para obtener eventos cercanos
    const radiusKM = 50;
    const kmPerDegree = 111.32; // Kilómetros por grado de latitud de la tierra

    const deltaLatDegrees = radiusKM / kmPerDegree;
    const deltaLonDegrees = radiusKM /
      (kmPerDegree * Math.cos(latitude * Math.PI / 180));

    const minLat = latitude - deltaLatDegrees;
    const maxLat = latitude + deltaLatDegrees;
    const minLon = longitude - deltaLonDegrees;
    const maxLon = longitude + deltaLonDegrees;

    const sql = `
      SELECT id, title, description, latitude, longitude,
      event_datetime_utc, icon_name,
      ((latitude - ?) * (latitude - ?)) +
      ((longitude - ?) * (longitude - ?) * ?) AS distance
      FROM community_events
      WHERE is_active = 1
      AND event_datetime_utc >= datetime('now', 'utc')
      AND longitude BETWEEN ? AND ?
      AND latitude BETWEEN ? AND ?
      ORDER BY distance ASC
      LIMIT 30
    `;

    const result = await db.execute({
      sql: sql,
      args: [
        latitude,
        latitude,
        longitude,
        longitude,
        Math.pow(Math.cos((latitude * Math.PI) / 180), 2),
        minLon,
        maxLon,
        minLat,
        maxLat,
      ],
    });

    const events = result.rows.map((row) => {
      const distance = calculateHaversine(
          latitude,
          longitude,
          row.latitude,
          row.longitude,
      );
      return {
        ...row,
        distance: parseFloat(distance.toFixed(2)),
      };
    });

    return {success: true, events};
  } catch (error) {
    console.error("Error fetching events:", error);
    return {success: false, message: "Error fetching events"};
  }
});

/**
 * Función para obtener los eventos que estás participando
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * datos.
 */
export const getParticipingEvents = onCall(async (request) => {
  const {accessToken} = request.data;

  if (!accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      SELECT ce.id, ce.title, ce.description, ce.latitude, ce.longitude,
      ce.event_datetime_utc, ce.icon_name
      FROM event_participants ep
      JOIN community_events ce ON ep.event_id = ce.id
      WHERE ep.user_id = ? AND ce.is_active = 1
    `;

    const result = await db.execute({
      sql: sql,
      args: [userId],
    });

    const events = result.rows;

    return {success: true, events};
  } catch (error) {
    console.error("Error fetching events:", error);
    return {success: false, message: "Error fetching events"};
  }
});

/**
 * Función para obtener los detalels del evento
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y evento.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * datos.
 */
export const getEventDetails = onCall(async (request) => {
  const {eventId, accessToken} = request.data;

  if (!eventId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  if (!userId) {
    return {success: false, message: "Invalid token"};
  }

  try {
    const sql = `
      SELECT id, title, description, body, notes, latitude, longitude,
      event_datetime_utc, max_attendees, icon_name, address, creator_user_id,
      participants
      FROM community_events
      WHERE id = ? AND is_active = 1
    `;

    const result = await db.execute({
      sql: sql,
      args: [eventId],
    });

    const eventDetails = result.rows[0];

    if (!eventDetails) {
      return {success: false, message: "Event not found"};
    }

    return {success: true, eventDetails};
  } catch (error) {
    console.error("Error fetching event details:", error);
    return {success: false, message: "Error fetching event details"};
  }
});

/**
 * Función para participar en un evento
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y evento.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const participateInEvent = onCall(async (request) => {
  const {eventId, accessToken} = request.data;

  if (!eventId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      INSERT INTO event_participants (event_id, user_id)
      VALUES (?, ?)
    `;

    const result = await db.execute({
      sql: sql,
      args: [eventId, userId],
    });

    if (result.rowsAffected === 0) {
      return {success: false, message: "Error participating in event"};
    }

    try {
      await giveUserXp(userId, 2);
    } catch (error) {
      console.error("Error giving XP to user:", error);
    }

    return {success: true, xp: 2};
  } catch (error) {
    console.error("Error participating in event:", error);
    return {success: false, message: "Error participating in event"};
  }
});

/**
 * Función para quitar tu participación en un evento
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y evento.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa.
 */
export const leaveEvent = onCall(async (request) => {
  const {eventId, accessToken} = request.data;

  if (!eventId || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);

  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }

  const userId = decodedToken.sub;

  try {
    const sql = `
      DELETE FROM event_participants
      WHERE event_id = ? AND user_id = ?
    `;

    const result = await db.execute({
      sql: sql,
      args: [eventId, userId],
    });

    const isDeleted = result.rowsAffected > 0;
    if (!isDeleted) {
      return {success: false, message: "Error leaving event"};
    }

    return {success: true};
  } catch (error) {
    console.error("Error leaving event:", error);
    return {success: false, message: "Error leaving event"};
  }
});

/**
 * Función para generar una URL firmada para subir un documento
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y del archivo.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * url.
 */
export const generateUploadDocLink = onCall(async (request) => {
  const {filename, contentType, petId, accessToken} = request.data;

  if (!filename || !contentType || !accessToken) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);
  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }
  const userId = decodedToken.sub;

  const safeFilename = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
  const filePath =
    `user-medical-docs/${userId}/${petId}/${Date.now()}-${safeFilename}`;
  const file = bucket.file(filePath);

  const options = {
    version: "v4",
    action: "write",
    expires: Date.now() + 15 * 60 * 1000, // 15 minutos validez
    contentType: contentType,
  };

  try {
    const [signedUrl] = await file.getSignedUrl(options);

    return {
      success: true,
      signedUrl,
      filePath,
    };
  } catch (error) {
    console.error("Error generating signed URL:", error);
    return {success: false, message: "Error generating signed URL"};
  }
});

/**
 * Función para añadir un historial medico
 * @param {Object} request - El objeto de solicitud que contiene los datos
 * del usuario y historial.
 * @returns {Object} - Un objeto que indica si la operación fue exitosa y
 * id.
 */
export const addMedicalRecord = onCall(async (request) => {
  const {
    petId,
    visitDate,
    vetName,
    diagnosis,
    treatment,
    notes,
    documentUrl,
    accessToken,
  } = request.data;

  if (!petId || !accessToken || !visitDate || !diagnosis) {
    return {success: false, message: "Missing required fields"};
  }

  const decodedToken = verifyAccessToken(accessToken);
  if (!decodedToken) {
    return {success: false, message: "Invalid token"};
  }
  const userId = decodedToken.sub;

  if (!userId) {
    return {success: false, message: "Invalid token"};
  }

  try {
    const sql = `
      INSERT INTO medical_records (pet_id, visit_date, vet_name, diagnosis,
      treatment, notes, document_url) VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    const result = await db.execute({
      sql: sql,
      args: [
        petId,
        visitDate,
        vetName,
        diagnosis,
        treatment,
        notes,
        documentUrl,
      ],
    });

    if (result.rowsAffected === 0) {
      return {success: false, message: "Error creating medical record"};
    }

    try {
      await giveUserXp(userId, 5);
    } catch (error) {
      console.error("Error giving XP to user:", error);
    }

    return {success: true, id: result.lastInsertRowid.toString(), xp: 5};
  } catch (error) {
    console.error("Error creating medical record:", error);
    return {success: false, message: "Error creating medical record"};
  }
});

/**
 * Función Haversine para calcular la distancia entre dos puntos
 * @param {number} lat1 - Latitud del primer punto
 * @param {number} lon1 - Longitud del primer punto
 * @param {number} lat2 - Latitud del segundo punto
 * @param {number} lon2 - Longitud del segundo punto
 * @return {number} - Distancia entre los dos puntos en kilómetros
 */
const calculateHaversine = (lat1, lon1, lat2, lon2) => {
  // Hacemos las operaciones de la formula de Haversine
  const R = 6371; // Radio de la Tierra en km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  // Devolvemos la distancia en kilómetros
  return R * c;
};

/**
 * Función para obtener el nivel de experiencia de un usuario
 * @param {number} userId
 * @return {Promise<Object|null>}
 */
const getUserXpLevel = async (userId) => {
  const sql = `
    SELECT xp FROM users WHERE id = ?
  `;

  try {
    const result = await db.execute({
      sql: sql,
      args: [userId],
    });

    if (result.rows.length === 0) {
      return null;
    }

    return result.rows[0];
  } catch (error) {
    console.error("Error fetching user XP level:", error);
    return null;
  }
};

/**
 * Función para dar experiencia a un usuario
 * @param {number} userId - ID del usuario
 * @param {number} xp - Cantidad de experiencia a añadir
 * @return {Promise<boolean>} - Verdadero si la operación fue exitosa
 */
const giveUserXp = async (userId, xp) => {
  if (!userId || !xp) {
    return false;
  }

  const sql = `
    UPDATE users SET xp = xp + ? WHERE id = ?
  `;

  try {
    const result = await db.execute({
      sql: sql,
      args: [xp, userId],
    });

    return result.rowsAffected > 0;
  } catch (error) {
    console.error("Error updating user XP:", error);
    return false;
  }
};

/**
 * Función que se ejecuta cada minuto para verificar y enviar recordatorios
 */
export const scheduledReminderChecker =
    onSchedule("every 1 minutes", async () => {
      try {
        const nowUtc = new Date();

        // Obtenemos la hora/minuto actual pero hasta el máximo de segundos
        const checkUntilUTC = new Date(nowUtc.getFullYear(), nowUtc.getMonth(),
            nowUtc.getDate(), nowUtc.getHours(), nowUtc.getMinutes(), 59, 999);

        // Obtenemos los recordatorios
        const getRemindersSql = `
          SELECT id, user_id, title, body, reminder_type, recurrence_rule,
          trigger_datetime_utc, next_trigger_datetime_utc, pet_id
          FROM reminders
          WHERE is_active = TRUE AND next_trigger_datetime_utc <= ?
        `;

        const remindersResult = await db.execute({
          sql: getRemindersSql,
          args: [checkUntilUTC.toISOString()],
        });

        if (remindersResult.rows.length === 0) {
          console.log("No reminders to process");
          return;
        }

        console.log("Recordatorios: ", remindersResult.rows);

        for (const reminder of remindersResult.rows) {
          const getTokenQuery = `
            SELECT fcm_token FROM fcm_tokens
            WHERE user_id = ?
          `;

          const tokenResult = await db.execute({
            sql: getTokenQuery,
            args: [reminder.user_id],
          });

          const fcmTokens = tokenResult.rows.map((row) => row.fcm_token);

          if (fcmTokens.length > 0) {
            // Enviamos las notificaciones
            const messagePayload = {
              notification: {
                title: reminder.title,
                body: reminder.body || "Tienes una nueva notificación",
              },
              data: {
                petId: String(reminder.pet_id),
                type: String(reminder.reminder_type),
                instructions: String(reminder.instructions) || null,
              },
              android: {
                priority: "high",
              },
              apns: {
                headers: {
                  "apns-priority": "10",
                  "apns-push-type": "alert",
                },
                payload: {
                  aps: {
                    sound: "default",
                  },
                },
              },
              tokens: fcmTokens,
            };

            try {
              const response = await admin.messaging()
                  .sendEachForMulticast(messagePayload);
              if (response.failureCount > 0) {
                // Si hay errores en enviar borramos los tokens si no son
                // validos
                await cleanInvalidTokens(response.responses,
                    fcmTokens, reminder.user_id);
              }
            } catch (error) {
              console.error("Error sending FCM message:", error);
            }
          } else {
            console.log("No FCM tokens found for user:", reminder.user_id);
          }

          await updateReminderAfterNotification(reminder);
        }
      } catch (error) {
        console.error("Error in scheduled function:", error);
      }
    });

const cleanInvalidTokens = async (responses, tokens, userId) => {
  const invalidTokens = [];

  responses.forEach((response, index) => {
    if (!response.success) {
      const errorCode = response.error.code;
      // Comprobamos los códigos de error de app borrada o caducados
      if (
        errorCode === "messaging/invalid-registration-token" ||
        errorCode === "messaging/registration-token-not-registered" ||
        errorCode === "messaging/mismatched-credential"
      ) {
        invalidTokens.push(tokens[index]);
      }
    }
  });

  if (invalidTokens.length > 0) {
    // Iteramos y borramos
    const deletePromises = invalidTokens.map((token) => {
      db.execute({
        sql: "DELETE FROM fcm_tokens WHERE user_id = ? AND fcm_token = ?",
        args: [userId, token],
      }).catch((error) => console.error("Error deleting token:", error));
    });
    await Promise.all(deletePromises);
    console.log("Deleted invalid tokens:", invalidTokens);
  }
};

const updateReminderAfterNotification = async (reminder) => {
  const {
    id,
    recurrence_rule: recurrenceRule,
    trigger_datetime_utc: triggerDatetime,
    next_trigger_datetime_utc: nextTriggerDatetime,
  } = reminder;

  if (recurrenceRule.toUpperCase() === "FREQ=NONE") {
    try {
      await db.execute({
        sql: "UPDATE reminders SET is_active = FALSE WHERE id = ?",
        args: [id],
      });
    } catch (error) {
      console.error("Error updating reminder:", error);
    }
  } else {
    let nextOccurrenceDate = null;

    try {
      const oldTriggerDate = new Date(triggerDatetime);
      const currentNextTriggerDate = new Date(nextTriggerDatetime);

      let rruleOptions;

      if (recurrenceRule.includes("DTSTART=")) {
        const ruleSet = rrulestr(recurrenceRule, {forceset: true});

        if (ruleSet._rrule.length > 0) {
          rruleOptions = ruleSet._rrule[0].options;
        } else {
          throw new Error("Invalid recurrence rule");
        }
      } else {
        rruleOptions = RRule.parseString(recurrenceRule);
        rruleOptions.dtstart = oldTriggerDate;
      }

      const rule = new RRule(rruleOptions);

      nextOccurrenceDate = rule.after(currentNextTriggerDate, false);
    } catch (error) {
      console.error("Error parsing next_trigger_datetime_utc:", error);
      nextOccurrenceDate = null;
      return;
    }

    if (nextOccurrenceDate) {
      try {
        const updateSQL= `
          UPDATE reminders SET next_trigger_datetime_utc = ? 
          WHERE id = ?`;
        await db.execute({
          sql: updateSQL,
          args: [nextOccurrenceDate.toISOString(), id],
        });
      } catch (error) {
        console.error("Error updating reminder:", error);
      }
    } else {
      try {
        await db.execute({
          sql: "UPDATE reminders SET is_active = FALSE WHERE id = ?",
          args: [id],
        });
      } catch (error) {
        console.error("Error updating reminder:", error);
      }
    }
  }
};
