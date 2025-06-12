🔐 AES Encryption/Decryption Tool (Web-Based)
This is a simple, elegant web tool for AES-based encryption and decryption of text messages, built using pure JavaScript and the crypto-js library. It runs entirely in the browser and requires no backend or server.

<!-- Optional: Add a screenshot of your tool -->

🚀 Features
🔐 AES-256 Encryption using crypto-js

🌙 Dark mode UI with smooth UX

⚡️ Works 100% offline (static HTML + JS)

🧠 No dependencies except crypto-js CDN

✅ Simple and secure message sharing

📁 Project Structure
rust
Copy
Edit
📂 encryption-tool/
├── index.html        ← Main web page
├── style.css         ← Dark mode styling
├── main.js           ← JS logic for encryption/decryption
└── README.md         ← You're reading it!
🛠️ How It Works
Enter a message and a secret key.

Click Encrypt to turn it into a secure ciphertext.

Copy and share the ciphertext.

To decrypt, paste the encrypted text back in and use the same secret key.

Note: Without the correct key, decryption will fail silently to protect your data.

📦 Hosting
This project is fully static and can be hosted using:

GitHub Pages

Netlify / Vercel / Surge

Local file (just open index.html in a browser)

To host on GitHub Pages:

Push the repo to GitHub.

Go to Settings → Pages.

Select your main or master branch as source.

Your site will be available at:
https://your-username.github.io/encryption-tool/

🔒 Tech Stack
HTML5
CSS3
JavaScript (ES6)
crypto-js



🙌 Credits
Made with 💙 by Shivansh Mehra
Licensed under MIT


