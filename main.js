function encryptMessage() {
  const msg = document.getElementById("message").value.trim();
  const key = document.getElementById("key").value;
  if (!msg || !key) return alert("Enter both message and key!");

  const cipher = CryptoJS.AES.encrypt(msg, key).toString();
  document.getElementById("output").value = cipher;
}

function decryptMessage() {
  const cipher = document.getElementById("message").value.trim();
  const key    = document.getElementById("key").value;
  if (!cipher || !key) return alert("Enter both encrypted text and key!");

  try {
    const bytes = CryptoJS.AES.decrypt(cipher, key);
    const plain = bytes.toString(CryptoJS.enc.Utf8);
    if (!plain) throw new Error();
    document.getElementById("output").value = plain;
  } catch {
    alert("Decryption failed. Wrong key or corrupted text.");
  }
}
