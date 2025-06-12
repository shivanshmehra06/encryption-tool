function encryptMessage() {
  const message = document.getElementById("message").value;
  const key = document.getElementById("key").value;

  if (!message || !key) {
    alert("Please provide both a message and key.");
    return;
  }

  const ciphertext = CryptoJS.AES.encrypt(message, key).toString();
  document.getElementById("output").value = ciphertext;
}

function decryptMessage() {
  const ciphertext = document.getElementById("message").value;
  const key = document.getElementById("key").value;

  if (!ciphertext || !key) {
    alert("Please provide both encrypted message and key.");
    return;
  }

  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);

    if (!decrypted) throw new Error("Invalid decryption");

    document.getElementById("output").value = decrypted;
  } catch (e) {
    alert("Failed to decrypt. Check your key or message.");
  }
}
