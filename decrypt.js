const SALT = '16232301442488928';
const ITERATIONS = 600000;
const IV_LENGTH = 12;

async function deriveKey(password) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return await window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: encoder.encode(SALT), iterations: ITERATIONS, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function decryptData(encryptedData, password) {
    const key = await deriveKey(password);
    const encryptedBytes = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));

    const iv = encryptedBytes.slice(0, IV_LENGTH);
    const authTag = encryptedBytes.slice(-16);
    const cipherText = encryptedBytes.slice(IV_LENGTH, -16);

    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv, additionalData: new Uint8Array([]), tagLength: 128 },
            key,
            new Uint8Array([...cipherText, ...authTag])
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        return null;
    }
}

