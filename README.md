# CipherSafe - Encryption Tool

![CipherSafe Screenshot](./assets/screenshot.png)

CipherSafe is a client-side encryption/decryption tool that works entirely in your browser. Your data never leaves your device, ensuring maximum privacy.

## Features

- **Secure Encryption**: Uses Web Crypto API for AES encryption (when available)
- **Multiple Algorithms**: Supports AES, DES, and XOR encryption methods
- **Local Storage**: Keeps history of your encrypted/decrypted messages
- **No Server Needed**: Works entirely client-side
- **Responsive Design**: Works on desktop and mobile devices

## How to Use

1. **Encrypt Text**:
   - Enter your text in the "Text to Encrypt" field
   - Provide a strong encryption key
   - Select an encryption method
   - Click "Encrypt"

2. **Decrypt Text**:
   - Paste your encrypted text in the "Text to Decrypt" field
   - Enter the same encryption key used to encrypt
   - Select the same encryption method
   - Click "Decrypt"

3. **History**:
   - All operations are saved in your browser's local storage
   - You can load, delete, export, or import history items

## Installation

To host this on GitHub Pages:

1. Fork this repository
2. Go to Settings > Pages
3. Select the main branch as the source
4. Click Save

The page will be available at `https://yourusername.github.io/encryption-tool`

## Security Notes

- **AES encryption** uses the Web Crypto API when available (modern browsers)
- **DES and XOR** are provided for compatibility but are less secure
- All data is stored only in your browser's local storage
- Encryption keys are never stored or transmitted

## License

MIT License - Free to use and modify
