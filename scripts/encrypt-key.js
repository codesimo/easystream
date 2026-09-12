#!/usr/bin/env node
/**
 * Cifra il Read Access Token TMDB (v4 auth) con una password, usando lo stesso
 * schema (PBKDF2-SHA256 -> AES-256-GCM) che il browser userà per decifrarlo
 * tramite Web Crypto API in index.html.
 *
 * Legge da variabili d'ambiente (mai da argomenti in chiaro, per non
 * finire nella cronologia della shell o nei log):
 *   TMDB_API_KEY      - il Read Access Token TMDB (v4, il token JWT lungo
 *                        da themoviedb.org/settings/api) da proteggere
 *   ENCRYPT_PASSWORD  - la password di sblocco
 *
 * Scrive encrypted-key.json nella root del progetto con:
 *   { salt, iv, ciphertext }  (tutti base64, tutti dati pubblici/inutili
 *   senza la password)
 *
 * Uso:
 *   TMDB_API_KEY=xxx ENCRYPT_PASSWORD=yyy node scripts/encrypt-key.js
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PBKDF2_ITERATIONS = 300000; // DEVE combaciare con PBKDF2_ITERATIONS in index.html
const SALT_LENGTH = 16; // bytes
const IV_LENGTH = 12;   // bytes, standard per AES-GCM

function main() {
  const apiKey = process.env.TMDB_API_KEY;
  const password = process.env.ENCRYPT_PASSWORD;

  if (!apiKey) {
    console.error("Errore: variabile d'ambiente TMDB_API_KEY mancante.");
    process.exit(1);
  }
  if (!password) {
    console.error("Errore: variabile d'ambiente ENCRYPT_PASSWORD mancante.");
    process.exit(1);
  }

  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  // Deriva una chiave AES-256 dalla password, stesso schema di crypto.subtle in index.html
  const derivedKey = crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    32, // 256 bit
    "sha256"
  );

  const cipher = crypto.createCipheriv("aes-256-gcm", derivedKey, iv);
  const encrypted = Buffer.concat([cipher.update(apiKey, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Web Crypto (AES-GCM) si aspetta il tag di autenticazione appeso in coda al ciphertext
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  const payload = {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    ciphertext: ciphertextWithTag.toString("base64")
  };

  const outputPath = path.join(__dirname, "..", "encrypted-key.json");
  fs.writeFileSync(outputPath, JSON.stringify(payload, null, 2) + "\n");

  console.log("File generato:", outputPath);
  console.log("(la password e la key in chiaro non vengono mai scritte su disco)");
}

main();