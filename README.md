# Post-Quantum File Encryptor (Windows Forms)

This project provides a basic Windows desktop application for encrypting and decrypting files using post-quantum cryptography (PQC). It utilizes a hybrid approach:

*   **ML-KEM (Kyber):** The NIST-standardized post-quantum Key Encapsulation Mechanism (based on Kyber) is used to securely establish a shared symmetric key using a public/private key pair.
*   **AES-GCM:** The established shared key is used with the industry-standard AES-GCM symmetric cipher for fast and authenticated encryption of the actual file content.

Built using C# (.NET Windows Forms) and the Bouncy Castle C# cryptography library (v2.5.1).

## Features

*   Generate ML-KEM (e.g., mlkem768) public/private key pairs and save them to files.
*   Select an input file and a recipient's public key file to encrypt the input file.
*   Select an encrypted input file and the corresponding private key file to decrypt the file.
*   Basic user interface with file browsing capabilities.

## Technology Stack

*   C#
*   .NET Windows Forms (Windows Only GUI)
*   Bouncy Castle C# (v2.5.1)
*   ML-KEM (Kyber)
*   AES-256-GCM

## Security Warning & Disclaimer ⚠️

This application is intended primarily as a **demonstration** of integrating PQC algorithms into a workflow.

*   **Insecure Key Storage:** Storing private keys as unencrypted files is **highly insecure** for protecting sensitive data in real-world scenarios. Proper key management solutions (like hardware security modules, OS key vaults, or strong password-based key protection) are essential for production use.
*   **Basic Implementation:** Error handling and security hardening are minimal.
*   **Use At Your Own Risk:** No guarantees are provided regarding security or functionality.

## How to Use

1.  **Generate Keys:** Click "Generate Key Pair", choose locations to save the public (`.key`) and private (`.key`) files. **Secure your private key!**
2.  **Share Public Key:** Give your `public.key` file to anyone who needs to send you encrypted files.
3.  **Encrypt:** Select the Input File, the recipient's `public.key` file, specify an Output File path, and click "Encrypt".
4.  **Decrypt:** Select the encrypted Input File, your *own* `private.key` file, specify an Output File path, and click "Decrypt".

## Building

Requires the .NET SDK (e.g., .NET 8 with Windows Desktop workload). Build using Visual Studio or the `dotnet build` command. Use `dotnet publish -c Release -r win-x64` to create a release build.

Alternatively download from the [Releases](https://github.com/uttaran-das/PqcFileEncryptor/releases).
