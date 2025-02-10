const fs = require('fs');
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const SALT = '16232301442488928';
const ITERATIONS = 600000;
const KEY_LENGTH = 32;
const IV_LENGTH = 12;

function deriveKey(password) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, SALT, ITERATIONS, KEY_LENGTH, 'sha256', (err, key) => {
            if (err) reject(err);
            resolve(key);
        });
    });
}

async function encryptData(plainText, password) {
    const key = await deriveKey(password);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([iv, encrypted, authTag]).toString('base64');
}

async function main() {
    try {
        const password = process.argv[2];
        if (!password) {
            console.error('Usage: node encrypt.js <password>');
            process.exit(1);
        }

        const data = fs.readFileSync('privateData.json', 'utf8');
        const encryptedText = await encryptData(data, password);

        fs.writeFileSync('encryptedData.json', encryptedText, null, 2);
        console.log('Data successfully encrypted and saved to encryptedData.json');
    } catch (error) {
        console.error('Error:', error);
    }
}

main();