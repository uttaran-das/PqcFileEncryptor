using System.Security.Cryptography; // For CryptographicException

namespace PqcFileEncryptor
{
    public partial class EncryptDecryptForm : Form
    {
        public EncryptDecryptForm()
        {
            InitializeComponent();

            try
            {
                // Get the path to the user's "My Documents" folder
                string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

                // Combine with default filenames
                txtPublicKeyFile.Text = Path.Combine(documentsPath, "pqc_public.key"); // Changed default name slightly
                txtPrivateKeyFile.Text = Path.Combine(documentsPath, "pqc_private.key"); // Changed default name slightly
            }
            catch (Exception ex)
            {
                // Handle potential errors getting the Documents path (rare, but possible)
                // Fallback to empty strings or another safe default if needed
                txtPublicKeyFile.Text = "";
                txtPrivateKeyFile.Text = "";
                UpdateStatus($"Could not set default key paths: {ex.Message}", true);
            }

            UpdateStatus("Ready");
        }

        private void UpdateStatus(string message, bool isError = false)
        {
            // Check if running on a different thread than the UI thread
            if (statusStrip1.InvokeRequired)
            {
                // Use Invoke to marshal the call back to the UI thread
                statusStrip1.Invoke(new Action(() => UpdateStatus(message, isError)));
            }
            else
            {
                // Now running on the UI thread, safe to update the control
                toolStripStatusLabel1.Text = $"Status: {message}";
            }
        }

        private void btnBrowseInput_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Select Input File";
                ofd.Filter = "All Files (*.*)|*.*";
                // Optional: Start in the directory of the currently selected input file, if any
                if (!string.IsNullOrWhiteSpace(txtInputFile.Text) && Directory.Exists(Path.GetDirectoryName(txtInputFile.Text)))
                {
                    ofd.InitialDirectory = Path.GetDirectoryName(txtInputFile.Text);
                }

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    // Set the input file path
                    txtInputFile.Text = ofd.FileName;

                    // --- Generate Default Output Path ---
                    try
                    {
                        string inputPath = txtInputFile.Text;
                        string inputDir = Path.GetDirectoryName(inputPath);
                        string inputNameWithoutExt = Path.GetFileNameWithoutExtension(inputPath);
                        string inputExt = Path.GetExtension(inputPath); // Gets the original extension, including the dot

                        string defaultOutputPath = "";

                        // Check if the input looks like an encrypted file already (for decryption suggestion)
                        if (!string.IsNullOrEmpty(inputExt) && inputExt.Equals(".enc", StringComparison.OrdinalIgnoreCase))
                        {
                            // Suggest removing ".enc" for decryption output
                            // Get the name *before* the .enc extension
                            string originalName = Path.GetFileNameWithoutExtension(inputNameWithoutExt); // Handles "file.txt.enc" -> "file.txt"
                            string originalExt = Path.GetExtension(inputNameWithoutExt); // Gets ".txt" from "file.txt"
                            defaultOutputPath = Path.Combine(inputDir, originalName + originalExt); // Combine to get "file.txt"

                            // Optional: Add a suffix if the suggested decrypted name is same as input
                            if (defaultOutputPath.Equals(inputPath, StringComparison.OrdinalIgnoreCase))
                            {
                                defaultOutputPath = Path.Combine(inputDir, inputNameWithoutExt + "_decrypted"); // e.g., file.enc -> file_decrypted
                            }
                            // Optional: Handle cases like "file.enc" where there's no inner extension
                            if (string.IsNullOrEmpty(originalExt) && !string.IsNullOrEmpty(originalName) && defaultOutputPath.Equals(Path.Combine(inputDir, originalName)))
                            {
                                defaultOutputPath = Path.Combine(inputDir, originalName + "_decrypted"); // e.g. secret.enc -> secret_decrypted
                            }


                        }
                        else
                        {
                            // Suggest adding ".enc" for encryption output
                            defaultOutputPath = Path.Combine(inputDir, inputNameWithoutExt + inputExt + ".enc");
                        }

                        txtOutputFile.Text = defaultOutputPath;
                    }
                    catch (ArgumentException argEx)
                    {
                        // Handle potential errors with invalid path characters if the input path is weird
                        UpdateStatus($"Could not generate default output path: {argEx.Message}", true);
                    }
                    catch (Exception ex) // Catch other potential Path exceptions
                    {
                        UpdateStatus($"Error generating default output path: {ex.Message}", true);
                    }
                    // --- End Generate Default Output Path ---
                }
            }
        }

        private void btnBrowseOutput_Click(object sender, EventArgs e)
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Title = "Select Output File Location";
                sfd.Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*";
                sfd.FilterIndex = 2; // Start with "All Files" as default might not be .enc

                string initialDirectory = "";
                string initialFileName = "";

                // --- Try to use the current output path text box content as the default ---
                if (!string.IsNullOrWhiteSpace(txtOutputFile.Text))
                {
                    try
                    {
                        initialFileName = Path.GetFileName(txtOutputFile.Text);
                        string dir = Path.GetDirectoryName(txtOutputFile.Text);
                        if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                        {
                            initialDirectory = dir;
                        }
                    }
                    catch (ArgumentException) { /* Ignore invalid path format in textbox */ }
                    catch (PathTooLongException) { /* Ignore */ }
                }

                // --- Fallback: If output textbox was empty/invalid, use input file path ---
                if (string.IsNullOrWhiteSpace(initialFileName))
                {
                    if (!string.IsNullOrWhiteSpace(txtInputFile.Text))
                    {
                        try
                        {
                            // Suggest adding .enc as a fallback default if output wasn't set
                            string inputFileName = Path.GetFileName(txtInputFile.Text);
                            initialFileName = inputFileName + ".enc"; // Simple append for fallback

                            string inputDir = Path.GetDirectoryName(txtInputFile.Text);
                            if (!string.IsNullOrEmpty(inputDir) && Directory.Exists(inputDir))
                            {
                                initialDirectory = inputDir; // Use input directory if output dir wasn't available
                            }
                        }
                        catch (ArgumentException) { /* Ignore invalid input path */ }
                        catch (PathTooLongException) { /* Ignore */ }
                    }
                }

                // --- Set SaveFileDialog properties ---
                if (!string.IsNullOrEmpty(initialDirectory))
                {
                    sfd.InitialDirectory = initialDirectory;
                }
                else if (!string.IsNullOrWhiteSpace(txtInputFile.Text)) // Second fallback for directory
                {
                    try
                    {
                        string inputDir = Path.GetDirectoryName(txtInputFile.Text);
                        if (!string.IsNullOrEmpty(inputDir) && Directory.Exists(inputDir))
                        {
                            sfd.InitialDirectory = inputDir;
                        }
                    }
                    catch { } // Ignore errors getting input dir
                }


                sfd.FileName = initialFileName; // Set the determined filename

                // Determine the likely filter based on suggested filename
                if (!string.IsNullOrEmpty(initialFileName))
                {
                    string ext = Path.GetExtension(initialFileName);
                    if (ext.Equals(".enc", StringComparison.OrdinalIgnoreCase))
                    {
                        sfd.Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*";
                        sfd.FilterIndex = 1; // Default to *.enc
                        sfd.DefaultExt = "enc";
                    }
                    else
                    {
                        sfd.Filter = "All Files (*.*)|*.*|Encrypted Files (*.enc)|*.enc";
                        sfd.FilterIndex = 1; // Default to *.*
                        sfd.DefaultExt = Path.HasExtension(initialFileName) ? Path.GetExtension(initialFileName).TrimStart('.') : "";
                    }
                }


                // --- Show Dialog and Update Textbox ---
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    txtOutputFile.Text = sfd.FileName;
                }
            }
        }

        private void btnBrowsePublicKey_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Select Public Key File";
                ofd.Filter = "Key Files (*.key)|*.key|All Files (*.*)|*.*";
                ofd.CheckFileExists = false; // Allow selecting non-existent for saving/generation

                // --- Suggest starting directory based on Input File ---
                if (!string.IsNullOrWhiteSpace(txtInputFile.Text))
                {
                    string inputDir = Path.GetDirectoryName(txtInputFile.Text);
                    if (!string.IsNullOrEmpty(inputDir) && Directory.Exists(inputDir))
                    {
                        ofd.InitialDirectory = inputDir;
                    }
                }
                // --- End Suggestion ---

                ofd.FileName = txtPublicKeyFile.Text; // Keep current text box value as default filename
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    txtPublicKeyFile.Text = ofd.FileName;
                }
            }
        }

        private void btnBrowsePrivateKey_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Select Private Key File";
                ofd.Filter = "Key Files (*.key)|*.key|All Files (*.*)|*.*";
                ofd.CheckFileExists = false; // Allow selecting non-existent for saving/generation

                // --- Suggest starting directory based on Input File ---
                // (Same logic as for the public key button)
                if (!string.IsNullOrWhiteSpace(txtInputFile.Text))
                {
                    try // Add try-catch for Path operations
                    {
                        string inputDir = Path.GetDirectoryName(txtInputFile.Text);
                        if (!string.IsNullOrEmpty(inputDir) && Directory.Exists(inputDir))
                        {
                            ofd.InitialDirectory = inputDir;
                        }
                    }
                    catch (ArgumentException) { /* Ignore if input path is invalid */ }
                    catch (PathTooLongException) { /* Ignore */ }
                }
                // --- End Suggestion ---

                // Keep current text box value as default filename suggestion
                // This allows the user to see the default 'kyber_private.key' or whatever is there
                if (!string.IsNullOrWhiteSpace(txtPrivateKeyFile.Text))
                {
                    try // Add try-catch for safety
                    {
                        // Set the FileName property, not just InitialDirectory, if you want
                        // the textbox value to be the default *file* selected/suggested
                        // in the dialog when it opens.
                        ofd.FileName = Path.GetFileName(txtPrivateKeyFile.Text);

                        // Also set InitialDirectory if the textbox contains a full path
                        string currentKeyDir = Path.GetDirectoryName(txtPrivateKeyFile.Text);
                        if (!string.IsNullOrEmpty(currentKeyDir) && Directory.Exists(currentKeyDir))
                        {
                            // Optionally, prioritize the directory from the textbox over the input file dir
                            ofd.InitialDirectory = currentKeyDir;
                        }

                    }
                    catch (ArgumentException) { /* Ignore if textbox path is invalid */ }
                }


                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    txtPrivateKeyFile.Text = ofd.FileName;
                }
            }
        }

        private async void btnGenerateKeys_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtPublicKeyFile.Text) || string.IsNullOrWhiteSpace(txtPrivateKeyFile.Text))
            {
                MessageBox.Show("Please specify paths for both public and private key files.", "Missing Key Paths", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Use the specified paths
            string pubKeyPath = txtPublicKeyFile.Text;
            string privKeyPath = txtPrivateKeyFile.Text;

            if (File.Exists(pubKeyPath) || File.Exists(privKeyPath))
            {
                var result = MessageBox.Show("One or both key files already exist at the specified locations. Overwrite?", "Confirm Overwrite", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (result == DialogResult.No) return;
            }

            UpdateStatus("Generating key pair...");
            this.Enabled = false; // Disable UI during operation
            try
            {
                // Run key generation on a background thread using Task.Run
                await Task.Run(() => CryptoService.GenerateAndSaveKeys(pubKeyPath, privKeyPath));

                UpdateStatus("Key pair generated successfully.");
                MessageBox.Show($"Keys generated and saved:\nPublic Key: {pubKeyPath}\nPrivate Key: {privKeyPath}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                UpdateStatus($"Key generation failed: {ex.Message}", true);
                MessageBox.Show($"Error generating keys: {ex.Message}\n\nCheck file permissions and path validity.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                this.Enabled = true; // Re-enable UI
            }
        }


        private async void btnEncrypt_Click(object sender, EventArgs e)
        {
            // Validate paths using the control names from your designer
            if (!File.Exists(txtInputFile.Text))
            {
                MessageBox.Show("Input file not found.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(txtOutputFile.Text))
            {
                MessageBox.Show("Please specify an output file path.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!File.Exists(txtPublicKeyFile.Text))
            {
                MessageBox.Show("Public key file not found.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (txtInputFile.Text.Equals(txtOutputFile.Text, StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("Input and Output file paths cannot be the same.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            UpdateStatus("Encrypting file...");
            this.Enabled = false;
            try
            {
                // Run encryption on a background thread
                await Task.Run(() =>
                    CryptoService.EncryptFile(txtInputFile.Text, txtOutputFile.Text, txtPublicKeyFile.Text)
                );
                UpdateStatus("Encryption successful.");
                MessageBox.Show($"File encrypted successfully:\n{txtOutputFile.Text}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);

            }
            catch (Exception ex)
            {
                UpdateStatus($"Encryption failed: {ex.Message}", true);
                MessageBox.Show($"Error encrypting file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                // Attempt to delete potentially partially written/corrupt output file
                try { if (File.Exists(txtOutputFile.Text)) File.Delete(txtOutputFile.Text); } catch { /* Ignore delete errors */ }
            }
            finally
            {
                this.Enabled = true;
            }
        }

        private async void btnDecrypt_Click(object sender, EventArgs e)
        {
            // Validate paths using the control names from your designer
            if (!File.Exists(txtInputFile.Text))
            {
                MessageBox.Show("Input file (encrypted) not found.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(txtOutputFile.Text))
            {
                MessageBox.Show("Please specify an output file path for decryption.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!File.Exists(txtPrivateKeyFile.Text))
            {
                MessageBox.Show("Private key file not found.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (txtInputFile.Text.Equals(txtOutputFile.Text, StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("Input and Output file paths cannot be the same.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }


            UpdateStatus("Decrypting file...");
            this.Enabled = false;
            try
            {
                // Run decryption on a background thread
                await Task.Run(() =>
                    CryptoService.DecryptFile(txtInputFile.Text, txtOutputFile.Text, txtPrivateKeyFile.Text)
                );
                UpdateStatus("Decryption successful.");
                MessageBox.Show($"File decrypted successfully:\n{txtOutputFile.Text}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (CryptographicException ex) // Catch specific crypto errors like auth failure
            {
                UpdateStatus($"Decryption failed: {ex.Message}", true);
                MessageBox.Show($"Decryption failed: {ex.Message}\n\n(This often means the wrong private key was used, the file is corrupt/tampered with, or it wasn't encrypted with the corresponding public key/algorithm).", "Decryption Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                // Decryption automatically deletes the output file on auth failure in CryptoService, no need to delete here.
            }
            catch (Exception ex)
            {
                UpdateStatus($"Decryption failed: {ex.Message}", true);
                MessageBox.Show($"Error decrypting file: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                // Attempt to delete potentially partially written/corrupt output file
                try { if (File.Exists(txtOutputFile.Text)) File.Delete(txtOutputFile.Text); } catch { /* Ignore delete errors */ }
            }
            finally
            {
                this.Enabled = true;
            }
        }
    }
}