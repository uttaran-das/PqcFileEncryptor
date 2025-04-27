using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Kems;

namespace PqcFileEncryptor
{
    public static class CryptoService
    {
        // --- Configuration ---
        // Using ML-KEM-768 (formerly Kyber768) - NIST PQC Level 3 Security
        private static readonly MLKemParameters PqcParameters = MLKemParameters.ml_kem_768;
        private const int AesKeySizeBits = 256;
        private const int AesGcmNonceSizeBits = 96;
        private const int AesGcmTagSizeBits = 128;

        // --- Key Management ---

        public static void GenerateAndSaveKeys(string publicKeyPath, string privateKeyPath)
        {
            var random = new SecureRandom();
            var keyGenParameters = new MLKemKeyGenerationParameters(random, PqcParameters);
            var keyPairGenerator = new MLKemKeyPairGenerator();
            keyPairGenerator.Init(keyGenParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            MLKemPublicKeyParameters publicKey = (MLKemPublicKeyParameters)keyPair.Public;
            MLKemPrivateKeyParameters privateKey = (MLKemPrivateKeyParameters)keyPair.Private;

            // --- Save keys using their direct byte encoding ---
            try
            {
                // Get the raw public key bytes
                byte[] publicKeyBytes = publicKey.GetEncoded();
                File.WriteAllBytes(publicKeyPath, publicKeyBytes);

                // Get the raw private key bytes
                byte[] privateKeyBytes = privateKey.GetEncoded();
                File.WriteAllBytes(privateKeyPath, privateKeyBytes);
            }
            catch (IOException ioEx)
            {
                throw new IOException($"Error saving key files: {ioEx.Message}", ioEx);
            }
            catch (Exception ex) // Catch other potential errors during GetEncoded
            {
                throw new Exception($"An unexpected error occurred while encoding/saving keys: {ex.Message}", ex);
            }
        }

        private static MLKemPublicKeyParameters LoadPublicKey(string publicKeyPath)
        {
            try
            {
                byte[] keyBytes = File.ReadAllBytes(publicKeyPath);
                // Use the static FromEncoding factory method
                return MLKemPublicKeyParameters.FromEncoding(PqcParameters, keyBytes);
            }
            catch (IOException ioEx)
            {
                // Re-throw IOException, possibly wrapped for context
                throw new IOException($"Error reading public key file '{publicKeyPath}': {ioEx.Message}", ioEx);
            }
            catch (ArgumentException argEx) // FromEncoding might throw this on bad data
            {
                // Re-throw ArgumentException, wrapped for context
                throw new CryptographicException($"Failed to parse public key from '{publicKeyPath}'. Data might be invalid or corrupt. Error: {argEx.Message}", argEx);
            }
            catch (Exception ex)
            {
                // Re-throw any other exception, wrapped for context
                throw new CryptographicException($"An unexpected error occurred loading public key from '{publicKeyPath}': {ex.Message}", ex);
            }
        }

        private static MLKemPrivateKeyParameters LoadPrivateKey(string privateKeyPath)
        {
            try
            {
                byte[] keyBytes = File.ReadAllBytes(privateKeyPath);
                return MLKemPrivateKeyParameters.FromEncoding(PqcParameters, keyBytes);
            }
            catch (IOException ioEx)
            {
                // Re-throw IOException, possibly wrapped for context
                throw new IOException($"Error reading private key file '{privateKeyPath}': {ioEx.Message}", ioEx);
            }
            catch (ArgumentException argEx) // FromEncoding might throw this on bad data
            {
                // Re-throw ArgumentException, wrapped for context
                throw new CryptographicException($"Failed to parse private key from '{privateKeyPath}'. Data might be invalid or corrupt. Error: {argEx.Message}", argEx);
            }
            catch (Exception ex)
            {
                // Re-throw any other exception, wrapped for context
                throw new CryptographicException($"An unexpected error occurred loading private key from '{privateKeyPath}': {ex.Message}", ex);
            }
        }

        // --- Encryption ---

        public static void EncryptFile(string inputFile, string outputFile, string publicKeyPath)
        {
            MLKemPublicKeyParameters publicKey = LoadPublicKey(publicKeyPath);
            var random = new SecureRandom();

            // 1. Generate ML-KEM encapsulation (Ciphertext + Shared Secret)

            //var kemGenerator = new MLKEMGenerator(random);
            //ISecretWithEncapsulation secretWithEncapsulation = kemGenerator.GenerateEncapsulated(publicKey);
            //byte[] kemEncapsulation = secretWithEncapsulation.GetEncapsulation(); // Ciphertext C
            //byte[] sharedSecret = secretWithEncapsulation.GetSecret();           // Shared secret K

            var encapsulator = new MLKemEncapsulator(PqcParameters);
            encapsulator.Init(new ParametersWithRandom(publicKey, random));

            byte[] kemEncapsulation = new byte[encapsulator.EncapsulationLength]; // Ciphertext C
            byte[] sharedSecret = new byte[encapsulator.SecretLength]; // Shared secret K
            encapsulator.Encapsulate(kemEncapsulation, 0, kemEncapsulation.Length, sharedSecret, 0, sharedSecret.Length);

            // 2. Derive AES Key and Nonce from the shared secret using HKDF
            byte[] aesKey = new byte[AesKeySizeBits / 8];
            byte[] nonce = new byte[AesGcmNonceSizeBits / 8];
            DeriveKeyAndNonce(sharedSecret, aesKey, nonce);

            // 3. Encrypt the file content with AES-GCM
            using (FileStream inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                // Write KEM Encapsulation Length (e.g., 4 bytes for Int32)
                outputStream.Write(BitConverter.GetBytes(kemEncapsulation.Length), 0, 4);
                // Write KEM Encapsulation Data (Ciphertext C)
                outputStream.Write(kemEncapsulation, 0, kemEncapsulation.Length);

                // Initialize AES-GCM Cipher
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(aesKey), AesGcmTagSizeBits, nonce);
                cipher.Init(true, parameters); // true for encryption

                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] encryptedBytes = new byte[cipher.GetUpdateOutputSize(bytesRead)];
                    int len = cipher.ProcessBytes(buffer, 0, bytesRead, encryptedBytes, 0);
                    outputStream.Write(encryptedBytes, 0, len);
                }

                // Finalize encryption (computes & appends the auth tag)
                byte[] finalBytes = new byte[cipher.GetOutputSize(0)];
                int finalLen = cipher.DoFinal(finalBytes, 0);
                outputStream.Write(finalBytes, 0, finalLen);
            }

            // Clear sensitive data
            Array.Clear(sharedSecret, 0, sharedSecret.Length);
            Array.Clear(aesKey, 0, aesKey.Length);
            Array.Clear(nonce, 0, nonce.Length);
        }


        // --- Decryption ---

        public static void DecryptFile(string inputFile, string outputFile, string privateKeyPath)
        {
            MLKemPrivateKeyParameters privateKey = LoadPrivateKey(privateKeyPath);

            using (FileStream inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                // 1. Read KEM Encapsulation Length Prefix
                byte[] lengthBytes = new byte[4];
                if (inputStream.Read(lengthBytes, 0, 4) != 4)
                    throw new InvalidOperationException($"Invalid encrypted file format in '{inputFile}'. Cannot read encapsulation length prefix.");

                int encapsulationLength = BitConverter.ToInt32(lengthBytes, 0);

                // Basic Sanity Check on Length
                if (encapsulationLength <= 0 || encapsulationLength > 4096) // Plausible size check
                {
                    throw new InvalidOperationException($"Invalid encapsulation length read from '{inputFile}' ({encapsulationLength} bytes). Length is non-positive or exceeds plausible size limit.");
                }

                // 2. Read KEM Encapsulation Data (Ciphertext C)
                byte[] kemEncapsulation = new byte[encapsulationLength];
                if (inputStream.Read(kemEncapsulation, 0, encapsulationLength) != encapsulationLength)
                    throw new InvalidOperationException($"Invalid encrypted file format in '{inputFile}'. Cannot read the full encapsulation data ({encapsulationLength} bytes).");

                // 3. Decrypt KEM encapsulation to get Shared Secret K
                byte[] sharedSecret;
                try
                {
                    //var kemExtractor = new MLKemKemExtractor(privateKey);
                    //sharedSecret = kemExtractor.ExtractSecret(kemEncapsulation);

                    var decapsulator = new MLKemDecapsulator(PqcParameters);
                    decapsulator.Init(privateKey);

                    sharedSecret = new byte[decapsulator.SecretLength];
                    decapsulator.Decapsulate(kemEncapsulation, 0, kemEncapsulation.Length, sharedSecret, 0, sharedSecret.Length);
                }
                catch (Exception ex)
                {
                    throw new CryptographicException($"Failed to extract ML-KEM shared secret using the provided private key. Encapsulation data might be corrupt/invalid for key '{privateKey.Parameters.Name}'. Error: {ex.Message}", ex);
                }

                // 4. Derive AES Key and Nonce
                byte[] aesKey = new byte[AesKeySizeBits / 8];
                byte[] nonce = new byte[AesGcmNonceSizeBits / 8];
                DeriveKeyAndNonce(sharedSecret, aesKey, nonce);

                // 5. Decrypt the file content with AES-GCM
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(aesKey), AesGcmTagSizeBits, nonce);
                cipher.Init(false, parameters); // false for decryption

                /*
                 * While a buffer of just 4096 might work correctly depending on the exact implementation details of GcmBlockCipher and Stream.Read, adding the tag size makes the code more robust and easier to reason about regarding the handling of the final block containing the authentication tag. The extra 16 bytes are negligible in terms of memory usage.
                 */
                byte[] buffer = new byte[4096 + AesGcmTagSizeBits / 8];
                int bytesRead;

                try
                {
                    while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        byte[] decryptedBytes = new byte[cipher.GetUpdateOutputSize(bytesRead)];
                        int len = cipher.ProcessBytes(buffer, 0, bytesRead, decryptedBytes, 0);
                        if (len > 0) outputStream.Write(decryptedBytes, 0, len);
                    }
                    byte[] finalBytes = new byte[cipher.GetOutputSize(0)];
                    int finalLen = cipher.DoFinal(finalBytes, 0);
                    if (finalLen > 0) outputStream.Write(finalBytes, 0, finalLen);
                }
                catch (InvalidCipherTextException ex) // GCM tag check failure
                {
                    outputStream.Close(); try { File.Delete(outputFile); } catch { /* Ignore */ }
                    throw new CryptographicException($"Decryption failed: AES-GCM data integrity check failed. Error: {ex.Message}", ex);
                }
                catch (Exception ex) // Other AES errors
                {
                    outputStream.Close(); try { File.Delete(outputFile); } catch { /* Ignore */ }
                    throw new CryptographicException($"An error occurred during AES-GCM decryption: {ex.Message}", ex);
                }

                // 6. Clear sensitive data
                if (sharedSecret != null) Array.Clear(sharedSecret, 0, sharedSecret.Length);
                if (aesKey != null) Array.Clear(aesKey, 0, aesKey.Length);
                if (nonce != null) Array.Clear(nonce, 0, nonce.Length);
            } // End using FileStream
        }

        // --- Helper: Key Derivation Function (HKDF) ---
        private static void DeriveKeyAndNonce(byte[] inputKeyMaterial, byte[] outputAesKey, byte[] outputNonce)
        {
            int outputLength = outputAesKey.Length + outputNonce.Length;
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(inputKeyMaterial, null, null));
            byte[] derivedBytes = new byte[outputLength];
            hkdf.GenerateBytes(derivedBytes, 0, outputLength);
            Buffer.BlockCopy(derivedBytes, 0, outputAesKey, 0, outputAesKey.Length);
            Buffer.BlockCopy(derivedBytes, outputAesKey.Length, outputNonce, 0, outputNonce.Length);
            Array.Clear(derivedBytes, 0, derivedBytes.Length);
        }
    }
}
