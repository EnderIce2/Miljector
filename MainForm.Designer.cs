
namespace Miljector
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
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
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.processComboBox = new System.Windows.Forms.ComboBox();
            this.injectButton = new System.Windows.Forms.Button();
            this.browseDLLButton = new System.Windows.Forms.Button();
            this.processLabel = new System.Windows.Forms.Label();
            this.infoLabel = new System.Windows.Forms.Label();
            this.refreshLinkLabel = new System.Windows.Forms.LinkLabel();
            this.aboutLinkLabel = new System.Windows.Forms.LinkLabel();
            this.processPictureBox = new System.Windows.Forms.PictureBox();
            this.DLLFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.settingsLinkLabel = new System.Windows.Forms.LinkLabel();
            ((System.ComponentModel.ISupportInitialize)(this.processPictureBox)).BeginInit();
            this.SuspendLayout();
            // 
            // processComboBox
            // 
            this.processComboBox.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(20)))), ((int)(((byte)(20)))), ((int)(((byte)(20)))));
            this.processComboBox.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.processComboBox.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(244)))), ((int)(((byte)(244)))), ((int)(((byte)(244)))));
            this.processComboBox.FormattingEnabled = true;
            this.processComboBox.Location = new System.Drawing.Point(65, 68);
            this.processComboBox.Name = "processComboBox";
            this.processComboBox.Size = new System.Drawing.Size(255, 24);
            this.processComboBox.TabIndex = 0;
            this.processComboBox.SelectedIndexChanged += new System.EventHandler(this.ProcessComboBox_SelectedIndexChanged);
            // 
            // injectButton
            // 
            this.injectButton.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(20)))), ((int)(((byte)(20)))), ((int)(((byte)(20)))));
            this.injectButton.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.injectButton.Location = new System.Drawing.Point(297, 126);
            this.injectButton.Name = "injectButton";
            this.injectButton.Size = new System.Drawing.Size(75, 23);
            this.injectButton.TabIndex = 1;
            this.injectButton.Text = "Inject";
            this.injectButton.UseVisualStyleBackColor = false;
            this.injectButton.Click += new System.EventHandler(this.InjectButton_Click);
            // 
            // browseDLLButton
            // 
            this.browseDLLButton.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(20)))), ((int)(((byte)(20)))), ((int)(((byte)(20)))));
            this.browseDLLButton.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.browseDLLButton.Location = new System.Drawing.Point(212, 126);
            this.browseDLLButton.Name = "browseDLLButton";
            this.browseDLLButton.Size = new System.Drawing.Size(79, 23);
            this.browseDLLButton.TabIndex = 2;
            this.browseDLLButton.Text = "Browse DLL";
            this.browseDLLButton.UseVisualStyleBackColor = false;
            this.browseDLLButton.Click += new System.EventHandler(this.BrowseDLLButton_Click);
            // 
            // processLabel
            // 
            this.processLabel.AutoSize = true;
            this.processLabel.Location = new System.Drawing.Point(81, 49);
            this.processLabel.Name = "processLabel";
            this.processLabel.Size = new System.Drawing.Size(48, 16);
            this.processLabel.TabIndex = 3;
            this.processLabel.Tag = "Process: ";
            this.processLabel.Text = "Process";
            // 
            // infoLabel
            // 
            this.infoLabel.AutoEllipsis = true;
            this.infoLabel.Cursor = System.Windows.Forms.Cursors.Default;
            this.infoLabel.Font = new System.Drawing.Font("Microsoft YaHei UI", 6.6F);
            this.infoLabel.Location = new System.Drawing.Point(12, 126);
            this.infoLabel.Name = "infoLabel";
            this.infoLabel.Size = new System.Drawing.Size(194, 23);
            this.infoLabel.TabIndex = 4;
            this.infoLabel.Tag = "Up-To-Date! {|} Out-Of-Date! Click here to update";
            this.infoLabel.Text = "Checking for updates...";
            this.infoLabel.TextAlign = System.Drawing.ContentAlignment.BottomLeft;
            this.infoLabel.UseCompatibleTextRendering = true;
            this.infoLabel.Click += new System.EventHandler(this.InfoLabel_Click);
            // 
            // refreshLinkLabel
            // 
            this.refreshLinkLabel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.refreshLinkLabel.AutoSize = true;
            this.refreshLinkLabel.LinkColor = System.Drawing.Color.DeepSkyBlue;
            this.refreshLinkLabel.Location = new System.Drawing.Point(273, 49);
            this.refreshLinkLabel.Name = "refreshLinkLabel";
            this.refreshLinkLabel.Size = new System.Drawing.Size(47, 16);
            this.refreshLinkLabel.TabIndex = 5;
            this.refreshLinkLabel.TabStop = true;
            this.refreshLinkLabel.Text = "Refresh";
            this.refreshLinkLabel.TextAlign = System.Drawing.ContentAlignment.TopRight;
            this.refreshLinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.RefreshLinkLabel_LinkClicked);
            // 
            // aboutLinkLabel
            // 
            this.aboutLinkLabel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.aboutLinkLabel.AutoSize = true;
            this.aboutLinkLabel.LinkColor = System.Drawing.Color.DeepSkyBlue;
            this.aboutLinkLabel.Location = new System.Drawing.Point(12, 9);
            this.aboutLinkLabel.Name = "aboutLinkLabel";
            this.aboutLinkLabel.Size = new System.Drawing.Size(41, 16);
            this.aboutLinkLabel.TabIndex = 7;
            this.aboutLinkLabel.TabStop = true;
            this.aboutLinkLabel.Text = "About";
            this.aboutLinkLabel.TextAlign = System.Drawing.ContentAlignment.TopRight;
            this.aboutLinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.AboutLinkLabel_LinkClicked);
            // 
            // processPictureBox
            // 
            this.processPictureBox.Location = new System.Drawing.Point(65, 49);
            this.processPictureBox.Name = "processPictureBox";
            this.processPictureBox.Size = new System.Drawing.Size(16, 16);
            this.processPictureBox.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.processPictureBox.TabIndex = 8;
            this.processPictureBox.TabStop = false;
            // 
            // DLLFileDialog
            // 
            this.DLLFileDialog.Filter = "DLL files|*.dll";
            this.DLLFileDialog.Title = "DLL";
            // 
            // settingsLinkLabel
            // 
            this.settingsLinkLabel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.settingsLinkLabel.AutoSize = true;
            this.settingsLinkLabel.LinkColor = System.Drawing.Color.DeepSkyBlue;
            this.settingsLinkLabel.Location = new System.Drawing.Point(12, 25);
            this.settingsLinkLabel.Name = "settingsLinkLabel";
            this.settingsLinkLabel.Size = new System.Drawing.Size(50, 16);
            this.settingsLinkLabel.TabIndex = 9;
            this.settingsLinkLabel.TabStop = true;
            this.settingsLinkLabel.Text = "Settings";
            this.settingsLinkLabel.TextAlign = System.Drawing.ContentAlignment.TopRight;
            this.settingsLinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.SettingsLinkLabel_LinkClicked);
            // 
            // MainForm
            // 
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.None;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(28)))), ((int)(((byte)(28)))), ((int)(((byte)(28)))));
            this.ClientSize = new System.Drawing.Size(384, 161);
            this.Controls.Add(this.settingsLinkLabel);
            this.Controls.Add(this.processPictureBox);
            this.Controls.Add(this.aboutLinkLabel);
            this.Controls.Add(this.refreshLinkLabel);
            this.Controls.Add(this.infoLabel);
            this.Controls.Add(this.processLabel);
            this.Controls.Add(this.browseDLLButton);
            this.Controls.Add(this.injectButton);
            this.Controls.Add(this.processComboBox);
            this.Font = new System.Drawing.Font("Microsoft YaHei UI", 8.25F);
            this.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(244)))), ((int)(((byte)(244)))), ((int)(((byte)(244)))));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.MinimumSize = new System.Drawing.Size(400, 200);
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Miljector";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.MainForm_FormClosed);
            this.Load += new System.EventHandler(this.MainForm_Load);
            ((System.ComponentModel.ISupportInitialize)(this.processPictureBox)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ComboBox processComboBox;
        private System.Windows.Forms.Button injectButton;
        private System.Windows.Forms.Button browseDLLButton;
        private System.Windows.Forms.Label processLabel;
        private System.Windows.Forms.Label infoLabel;
        private System.Windows.Forms.LinkLabel refreshLinkLabel;
        private System.Windows.Forms.LinkLabel aboutLinkLabel;
        private System.Windows.Forms.PictureBox processPictureBox;
        private System.Windows.Forms.OpenFileDialog DLLFileDialog;
        private System.Windows.Forms.LinkLabel settingsLinkLabel;
    }
}

