let pyodideReady = false;

async function loadPyodideAndPackages() {
  window.pyodide = await loadPyodide();
  await pyodide.loadPackage("micropip");
  await pyodide.runPythonAsync(`
    import micropip
    await micropip.install("pycryptodome")
  `);
  await pyodide.runPythonAsync(`
    from Crypto.Cipher import AES
    import base64
    import hashlib

    def pad(s): return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    def unpad(s): return s[:-ord(s[len(s) - 1:])]

    def encrypt(text, key):
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(text).encode())
        return base64.b64encode(encrypted).decode()

    def decrypt(enc, key):
        key = hashlib.sha256(key.encode()).digest()
        enc = base64.b64decode(enc)
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(enc).decode())
  `);
  pyodideReady = true;
}

loadPyodideAndPackages();

async function encryptMessage() {
  if (!pyodideReady) return alert("Python still loading...");
  const text = document.getElementById("message").value;
  const key = document.getElementById("key").value;
  const result = await pyodide.runPythonAsync(`encrypt("""${text}""", """${key}""")`);
  document.getElementById("output").value = result;
}

async function decryptMessage() {
  if (!pyodideReady) return alert("Python still loading...");
  const enc = document.getElementById("message").value;
  const key = document.getElementById("key").value;
  try {
    const result = await pyodide.runPythonAsync(`decrypt("""${enc}""", """${key}""")`);
    document.getElementById("output").value = result;
  } catch (e) {
    alert("Decryption failed. Check your key or message.");
  }
}

function saveEncrypted() {
  const data = document.getElementById("output").value;
  if (data) {
    localStorage.setItem("savedEncrypted", data);
    alert("Encrypted message saved!");
  } else {
    alert("Nothing to save!");
  }
}

function loadEncrypted() {
  const data = localStorage.getItem("savedEncrypted");
  if (data) {
    document.getElementById("message").value = data;
    alert("Encrypted message loaded.");
  } else {
    alert("No saved message found.");
  }
}
