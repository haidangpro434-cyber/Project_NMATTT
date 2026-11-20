// =========================================================
// PHẦN 1: BẢNG HẰNG SỐ AES (S-BOX, INV S-BOX, RCON)
// =========================================================
const SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Tự sinh bảng InvS-Box nghịch đảo từ S-Box
const INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) {
    INV_SBOX[SBOX[i]] = i;
}

// Hằng số vòng (Round Constants) cho bước sinh khóa con
const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// =========================================================
// PHẦN 2: CÁC PHÉP TOÁN LÕI CỦA AES
// =========================================================

// Phép nhân trong trường hữu hạn GF(2^8) cho MixColumns
function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hiBit = a & 0x80;
        a = (a << 1) & 0xff;
        if (hiBit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// Sinh toàn bộ khóa vòng (Key Expansion) cho 128/192/256-bit
function keyExpansion(keyBytes) {
    const Nk = keyBytes.length / 4; // 4, 6 hoặc 8 word
    const Nr = Nk + 6; // 10, 12 hoặc 14 vòng
    const totalWords = 4 * (Nr + 1);
    const w = new Uint8Array(totalWords * 4);

    w.set(keyBytes);

    const temp = new Uint8Array(4);
    for (let i = Nk; i < totalWords; i++) {
        temp[0] = w[(i - 1) * 4];
        temp[1] = w[(i - 1) * 4 + 1];
        temp[2] = w[(i - 1) * 4 + 2];
        temp[3] = w[(i - 1) * 4 + 3];

        if (i % Nk === 0) {
            // RotWord + SubWord + XOR Rcon
            const t = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[i / Nk];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t];
        } else if (Nk > 6 && i % Nk === 4) {
            // Bước bổ sung riêng cho AES-256
            for (let j = 0; j < 4; j++) temp[j] = SBOX[temp[j]];
        }

        for (let j = 0; j < 4; j++) {
            w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ temp[j];
        }
    }

    return { expandedKey: w, Nr };
}

function addRoundKey(state, expandedKey, round) {
    const offset = round * 16;
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[offset + i];
    }
}

function subBytes(state) {
    for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

function invSubBytes(state) {
    for (let i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
}

function shiftRows(s) {
    // Hàng 1 dịch trái 1
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // Hàng 2 dịch trái 2
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    // Hàng 3 dịch trái 3 (dịch phải 1)
    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

function invShiftRows(s) {
    // Hàng 1 dịch phải 1
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    // Hàng 2 dịch phải 2
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    // Hàng 3 dịch phải 3 (dịch trái 1)
    t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

function mixColumns(s) {
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i],
            a1 = s[i + 1],
            a2 = s[i + 2],
            a3 = s[i + 3];
        s[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        s[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

function invMixColumns(s) {
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i],
            a1 = s[i + 1],
            a2 = s[i + 2],
            a3 = s[i + 3];
        s[i] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        s[i + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        s[i + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        s[i + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

// Mã hóa 1 khối 16 byte
function encryptBlock(block, expandedKey, Nr) {
    const state = new Uint8Array(block);
    addRoundKey(state, expandedKey, 0);

    for (let round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey, Nr);
    return state;
}

// Giải mã 1 khối 16 byte
function decryptBlock(block, expandedKey, Nr) {
    const state = new Uint8Array(block);
    addRoundKey(state, expandedKey, Nr);

    for (let round = Nr - 1; round >= 1; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey, round);
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expandedKey, 0);
    return state;
}

// =========================================================
// PHẦN 3: PKCS#7 PADDING & CHẾ ĐỘ CBC
// =========================================================

function pkcs7Pad(bytes) {
    const padLen = 16 - (bytes.length % 16);
    const padded = new Uint8Array(bytes.length + padLen);
    padded.set(bytes);
    padded.fill(padLen, bytes.length);
    return padded;
}

function pkcs7Unpad(bytes) {
    if (bytes.length === 0 || bytes.length % 16 !== 0) {
        throw new Error("Độ dài dữ liệu không phải bội số của 16 byte.");
    }
    const padLen = bytes[bytes.length - 1];
    if (padLen < 1 || padLen > 16) {
        throw new Error("Padding PKCS#7 không hợp lệ (sai Key, sai IV hoặc sai bản mã).");
    }
    for (let i = bytes.length - padLen; i < bytes.length; i++) {
        if (bytes[i] !== padLen) {
            throw new Error("Padding PKCS#7 không hợp lệ (sai Key, sai IV hoặc sai bản mã).");
        }
    }
    return bytes.slice(0, bytes.length - padLen);
}

function aesCbcEncrypt(plainBytes, keyBytes, ivBytes) {
    const { expandedKey, Nr } = keyExpansion(keyBytes);
    const padded = pkcs7Pad(plainBytes);
    const output = new Uint8Array(padded.length);
    let prevBlock = ivBytes;

    for (let i = 0; i < padded.length; i += 16) {
        const block = new Uint8Array(16);
        for (let j = 0; j < 16; j++) {
            block[j] = padded[i + j] ^ prevBlock[j];
        }
        const encrypted = encryptBlock(block, expandedKey, Nr);
        output.set(encrypted, i);
        prevBlock = encrypted;
    }

    return output;
}

function aesCbcDecrypt(cipherBytes, keyBytes, ivBytes) {
    if (cipherBytes.length === 0 || cipherBytes.length % 16 !== 0) {
        throw new Error("Bản mã AES-CBC phải có độ dài là bội số của 16 byte.");
    }
    const { expandedKey, Nr } = keyExpansion(keyBytes);
    const output = new Uint8Array(cipherBytes.length);
    let prevBlock = ivBytes;

    for (let i = 0; i < cipherBytes.length; i += 16) {
        const cipherBlock = cipherBytes.slice(i, i + 16);
        const decrypted = decryptBlock(cipherBlock, expandedKey, Nr);
        for (let j = 0; j < 16; j++) {
            output[i + j] = decrypted[j] ^ prevBlock[j];
        }
        prevBlock = cipherBlock;
    }

    return pkcs7Unpad(output);
}

// =========================================================
// PHẦN 4: CHUYỂN ĐỔI ĐỊNH DẠNG & GẮN SỰ KIỆN GIAO DIỆN
// =========================================================

const keyFormatEl = document.getElementById("keyFormat");
const cipherFormatEl = document.getElementById("cipherFormat");
const keyInput = document.getElementById("key");
const ivInput = document.getElementById("iv");
const keyHexOutput = document.getElementById("keyHex");
const roundKeysOutput = document.getElementById("roundKeys");
const inputText = document.getElementById("inputText");
const outputText = document.getElementById("outputText");

const btnGenKey = document.getElementById("btnGenKey");
const btnEncrypt = document.getElementById("btnEncrypt");
const btnDecrypt = document.getElementById("btnDecrypt");

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBytes(base64) {
    const binary = atob(base64.trim());
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToSpacedHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
}

function hexToBytes(hex) {
    const clean = hex.replace(/\s+/g, "");
    if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
        throw new Error("Chuỗi Hex không hợp lệ.");
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
    }
    return bytes;
}

function parseBytes(str, format) {
    if (format === "utf8") return encoder.encode(str);
    if (format === "hex") return hexToBytes(str);
    if (format === "base64") return base64ToBytes(str);
    throw new Error("Định dạng không hỗ trợ.");
}

function randomFormatted(byteLen, format) {
    if (format === "utf8") {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let res = "";
        for (let i = 0; i < byteLen; i++) {
            res += chars[Math.floor(Math.random() * chars.length)];
        }
        return res;
    }
    const bytes = new Uint8Array(byteLen);
    for (let i = 0; i < byteLen; i++) bytes[i] = Math.floor(Math.random() * 256);
    return format === "hex" ? bytesToHex(bytes) : bytesToBase64(bytes);
}

// Hiển thị mã Key (Hex) và toàn bộ khóa vòng từ Key Expansion
function updateKeyDisplay() {
    const rawKey = keyInput.value;
    if (!rawKey) {
        keyHexOutput.value = "";
        roundKeysOutput.value = "";
        return;
    }

    try {
        const keyBytes = parseBytes(rawKey, keyFormatEl.value);
        keyHexOutput.value = `${bytesToSpacedHex(keyBytes)} (${keyBytes.length} byte)`;

        if (![16, 24, 32].includes(keyBytes.length)) {
            roundKeysOutput.value = `Cần đúng 16, 24 hoặc 32 byte để sinh khóa vòng (hiện tại: ${keyBytes.length} byte).`;
            return;
        }

        const { expandedKey, Nr } = keyExpansion(keyBytes);
        const lines = [];
        for (let r = 0; r <= Nr; r++) {
            const rk = expandedKey.slice(r * 16, (r + 1) * 16);
            lines.push(`Round ${String(r).padStart(2, "0")}: ${bytesToSpacedHex(rk)}`);
        }
        roundKeysOutput.value = lines.join("\n");
    } catch (err) {
        keyHexOutput.value = "Định dạng Key chưa hợp lệ";
        roundKeysOutput.value = "";
    }
}

function getValidatedKeyAndIV() {
    const fmt = keyFormatEl.value;
    const keyBytes = parseBytes(keyInput.value, fmt);
    const ivBytes = parseBytes(ivInput.value, fmt);

    if (![16, 24, 32].includes(keyBytes.length)) {
        throw new Error(`Key phải có độ dài 16, 24 hoặc 32 byte (hiện tại: ${keyBytes.length} byte).`);
    }
    if (ivBytes.length !== 16) {
        throw new Error(`IV phải có độ dài đúng 16 byte (hiện tại: ${ivBytes.length} byte).`);
    }
    return { keyBytes, ivBytes };
}

keyInput.addEventListener("input", updateKeyDisplay);
keyFormatEl.addEventListener("change", updateKeyDisplay);

btnGenKey.addEventListener("click", () => {
    const fmt = keyFormatEl.value;
    keyInput.value = randomFormatted(16, fmt);
    ivInput.value = randomFormatted(16, fmt);
    updateKeyDisplay();
});

btnEncrypt.addEventListener("click", () => {
    const text = inputText.value;
    if (!text) {
        alert("Vui lòng nhập văn bản cần mã hóa.");
        return;
    }
    try {
        const { keyBytes, ivBytes } = getValidatedKeyAndIV();
        updateKeyDisplay();
        const cipherBytes = aesCbcEncrypt(encoder.encode(text), keyBytes, ivBytes);
        outputText.value =
            cipherFormatEl.value === "hex" ? bytesToHex(cipherBytes) : bytesToBase64(cipherBytes);
    } catch (err) {
        alert("Lỗi mã hóa: " + err.message);
    }
});

btnDecrypt.addEventListener("click", () => {
    const cipher = inputText.value.trim();
    if (!cipher) {
        alert("Vui lòng nhập chuỗi cần giải mã.");
        return;
    }
    try {
        const { keyBytes, ivBytes } = getValidatedKeyAndIV();
        updateKeyDisplay();
        const cipherBytes = parseBytes(cipher, cipherFormatEl.value);
        const plainBytes = aesCbcDecrypt(cipherBytes, keyBytes, ivBytes);
        outputText.value = decoder.decode(plainBytes);
    } catch (err) {
        outputText.value = "";
        alert("Lỗi giải mã: " + err.message);
    }
});