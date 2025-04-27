namespace PqcFileEncryptor
{
    partial class EncryptDecryptForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            lblInputFile = new Label();
            txtInputFile = new TextBox();
            btnBrowseInput = new Button();
            lblOutputFile = new Label();
            txtOutputFile = new TextBox();
            btnBrowseOutput = new Button();
            lblPublicKeyFile = new Label();
            txtPublicKeyFile = new TextBox();
            btnBrowsePublicKey = new Button();
            btnBrowsePrivateKey = new Button();
            txtPrivateKeyFile = new TextBox();
            lblPrivateKeyFile = new Label();
            btnGenerateKeys = new Button();
            btnEncrypt = new Button();
            btnDecrypt = new Button();
            statusStrip1 = new StatusStrip();
            toolStripStatusLabel1 = new ToolStripStatusLabel();
            statusStrip1.SuspendLayout();
            SuspendLayout();
            // 
            // lblInputFile
            // 
            lblInputFile.AutoSize = true;
            lblInputFile.Location = new Point(15, 20);
            lblInputFile.Name = "lblInputFile";
            lblInputFile.Size = new Size(59, 15);
            lblInputFile.TabIndex = 0;
            lblInputFile.Text = "Input File:";
            // 
            // txtInputFile
            // 
            txtInputFile.Location = new Point(120, 17);
            txtInputFile.Name = "txtInputFile";
            txtInputFile.ReadOnly = true;
            txtInputFile.Size = new Size(230, 23);
            txtInputFile.TabIndex = 1;
            // 
            // btnBrowseInput
            // 
            btnBrowseInput.Location = new Point(360, 16);
            btnBrowseInput.Name = "btnBrowseInput";
            btnBrowseInput.Size = new Size(40, 23);
            btnBrowseInput.TabIndex = 2;
            btnBrowseInput.Text = "...";
            btnBrowseInput.UseVisualStyleBackColor = true;
            btnBrowseInput.Click += btnBrowseInput_Click;
            // 
            // lblOutputFile
            // 
            lblOutputFile.AutoSize = true;
            lblOutputFile.Location = new Point(15, 50);
            lblOutputFile.Name = "lblOutputFile";
            lblOutputFile.Size = new Size(69, 15);
            lblOutputFile.TabIndex = 3;
            lblOutputFile.Text = "Output File:";
            // 
            // txtOutputFile
            // 
            txtOutputFile.Location = new Point(120, 47);
            txtOutputFile.Name = "txtOutputFile";
            txtOutputFile.ReadOnly = true;
            txtOutputFile.Size = new Size(230, 23);
            txtOutputFile.TabIndex = 4;
            // 
            // btnBrowseOutput
            // 
            btnBrowseOutput.Location = new Point(360, 46);
            btnBrowseOutput.Name = "btnBrowseOutput";
            btnBrowseOutput.Size = new Size(40, 23);
            btnBrowseOutput.TabIndex = 5;
            btnBrowseOutput.Text = "...";
            btnBrowseOutput.UseVisualStyleBackColor = true;
            btnBrowseOutput.Click += btnBrowseOutput_Click;
            // 
            // lblPublicKeyFile
            // 
            lblPublicKeyFile.AutoSize = true;
            lblPublicKeyFile.Location = new Point(15, 80);
            lblPublicKeyFile.Name = "lblPublicKeyFile";
            lblPublicKeyFile.Size = new Size(86, 15);
            lblPublicKeyFile.TabIndex = 6;
            lblPublicKeyFile.Text = "Public Key File:";
            // 
            // txtPublicKeyFile
            // 
            txtPublicKeyFile.Location = new Point(120, 77);
            txtPublicKeyFile.Name = "txtPublicKeyFile";
            txtPublicKeyFile.ReadOnly = true;
            txtPublicKeyFile.Size = new Size(230, 23);
            txtPublicKeyFile.TabIndex = 7;
            // 
            // btnBrowsePublicKey
            // 
            btnBrowsePublicKey.Location = new Point(360, 76);
            btnBrowsePublicKey.Name = "btnBrowsePublicKey";
            btnBrowsePublicKey.Size = new Size(40, 23);
            btnBrowsePublicKey.TabIndex = 8;
            btnBrowsePublicKey.Text = "...";
            btnBrowsePublicKey.UseVisualStyleBackColor = true;
            btnBrowsePublicKey.Click += btnBrowsePublicKey_Click;
            // 
            // btnBrowsePrivateKey
            // 
            btnBrowsePrivateKey.Location = new Point(360, 107);
            btnBrowsePrivateKey.Name = "btnBrowsePrivateKey";
            btnBrowsePrivateKey.Size = new Size(40, 23);
            btnBrowsePrivateKey.TabIndex = 11;
            btnBrowsePrivateKey.Text = "...";
            btnBrowsePrivateKey.UseVisualStyleBackColor = true;
            btnBrowsePrivateKey.Click += btnBrowsePrivateKey_Click;
            // 
            // txtPrivateKeyFile
            // 
            txtPrivateKeyFile.Location = new Point(120, 108);
            txtPrivateKeyFile.Name = "txtPrivateKeyFile";
            txtPrivateKeyFile.ReadOnly = true;
            txtPrivateKeyFile.Size = new Size(230, 23);
            txtPrivateKeyFile.TabIndex = 10;
            // 
            // lblPrivateKeyFile
            // 
            lblPrivateKeyFile.AutoSize = true;
            lblPrivateKeyFile.Location = new Point(15, 111);
            lblPrivateKeyFile.Name = "lblPrivateKeyFile";
            lblPrivateKeyFile.Size = new Size(89, 15);
            lblPrivateKeyFile.TabIndex = 9;
            lblPrivateKeyFile.Text = "Private Key File:";
            // 
            // btnGenerateKeys
            // 
            btnGenerateKeys.Location = new Point(139, 158);
            btnGenerateKeys.Name = "btnGenerateKeys";
            btnGenerateKeys.Size = new Size(150, 35);
            btnGenerateKeys.TabIndex = 12;
            btnGenerateKeys.Text = "Generate Key Pair";
            btnGenerateKeys.UseVisualStyleBackColor = true;
            btnGenerateKeys.Click += btnGenerateKeys_Click;
            // 
            // btnEncrypt
            // 
            btnEncrypt.Location = new Point(40, 205);
            btnEncrypt.Name = "btnEncrypt";
            btnEncrypt.Size = new Size(150, 35);
            btnEncrypt.TabIndex = 13;
            btnEncrypt.Text = "Encrypt";
            btnEncrypt.UseVisualStyleBackColor = true;
            btnEncrypt.Click += btnEncrypt_Click;
            // 
            // btnDecrypt
            // 
            btnDecrypt.Location = new Point(230, 205);
            btnDecrypt.Name = "btnDecrypt";
            btnDecrypt.Size = new Size(150, 35);
            btnDecrypt.TabIndex = 14;
            btnDecrypt.Text = "Decrypt";
            btnDecrypt.UseVisualStyleBackColor = true;
            btnDecrypt.Click += btnDecrypt_Click;
            // 
            // statusStrip1
            // 
            statusStrip1.Items.AddRange(new ToolStripItem[] { toolStripStatusLabel1 });
            statusStrip1.Location = new Point(0, 289);
            statusStrip1.Name = "statusStrip1";
            statusStrip1.Size = new Size(434, 22);
            statusStrip1.TabIndex = 15;
            statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            toolStripStatusLabel1.Size = new Size(77, 17);
            toolStripStatusLabel1.Text = "Status: Ready";
            // 
            // EncryptDecryptForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(434, 311);
            Controls.Add(statusStrip1);
            Controls.Add(btnDecrypt);
            Controls.Add(btnEncrypt);
            Controls.Add(btnGenerateKeys);
            Controls.Add(btnBrowsePrivateKey);
            Controls.Add(txtPrivateKeyFile);
            Controls.Add(lblPrivateKeyFile);
            Controls.Add(btnBrowsePublicKey);
            Controls.Add(txtPublicKeyFile);
            Controls.Add(lblPublicKeyFile);
            Controls.Add(btnBrowseOutput);
            Controls.Add(txtOutputFile);
            Controls.Add(lblOutputFile);
            Controls.Add(btnBrowseInput);
            Controls.Add(txtInputFile);
            Controls.Add(lblInputFile);
            Name = "EncryptDecryptForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Encrypt/Decrypt";
            statusStrip1.ResumeLayout(false);
            statusStrip1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label lblInputFile;
        private TextBox txtInputFile;
        private Button btnBrowseInput;
        private Label lblOutputFile;
        private TextBox txtOutputFile;
        private Button btnBrowseOutput;
        private Label lblPublicKeyFile;
        private TextBox txtPublicKeyFile;
        private Button btnBrowsePublicKey;
        private Button btnBrowsePrivateKey;
        private TextBox txtPrivateKeyFile;
        private Label lblPrivateKeyFile;
        private Button btnGenerateKeys;
        private Button btnEncrypt;
        private Button btnDecrypt;
        private StatusStrip statusStrip1;
        private ToolStripStatusLabel toolStripStatusLabel1;
    }
}
