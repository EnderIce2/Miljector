
namespace Miljector
{
    partial class SettingsForm
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
            this.useAlternativeInjectionCheckBox = new System.Windows.Forms.CheckBox();
            this.okButton = new System.Windows.Forms.Button();
            this.checkForUpdatesCheckBox = new System.Windows.Forms.CheckBox();
            this.enableDiscordRPCStatusCheckBox = new System.Windows.Forms.CheckBox();
            this.Gen2InjectionCheckBox = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // useAlternativeInjectionCheckBox
            // 
            this.useAlternativeInjectionCheckBox.AutoSize = true;
            this.useAlternativeInjectionCheckBox.Location = new System.Drawing.Point(12, 35);
            this.useAlternativeInjectionCheckBox.Name = "useAlternativeInjectionCheckBox";
            this.useAlternativeInjectionCheckBox.Size = new System.Drawing.Size(204, 17);
            this.useAlternativeInjectionCheckBox.TabIndex = 0;
            this.useAlternativeInjectionCheckBox.Text = "Use Alternative Injection (C++ && ASM)";
            this.useAlternativeInjectionCheckBox.UseVisualStyleBackColor = true;
            this.useAlternativeInjectionCheckBox.CheckedChanged += new System.EventHandler(this.UseAlternativeInjectionCheckBox_CheckedChanged);
            // 
            // okButton
            // 
            this.okButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.okButton.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(20)))), ((int)(((byte)(20)))), ((int)(((byte)(20)))));
            this.okButton.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.okButton.Location = new System.Drawing.Point(147, 101);
            this.okButton.Name = "okButton";
            this.okButton.Size = new System.Drawing.Size(75, 23);
            this.okButton.TabIndex = 2;
            this.okButton.Text = "&OK";
            this.okButton.UseVisualStyleBackColor = false;
            this.okButton.Click += new System.EventHandler(this.OkButton_Click);
            // 
            // checkForUpdatesCheckBox
            // 
            this.checkForUpdatesCheckBox.AutoSize = true;
            this.checkForUpdatesCheckBox.Location = new System.Drawing.Point(12, 58);
            this.checkForUpdatesCheckBox.Name = "checkForUpdatesCheckBox";
            this.checkForUpdatesCheckBox.Size = new System.Drawing.Size(118, 17);
            this.checkForUpdatesCheckBox.TabIndex = 3;
            this.checkForUpdatesCheckBox.Text = "Check For Updates";
            this.checkForUpdatesCheckBox.UseVisualStyleBackColor = true;
            this.checkForUpdatesCheckBox.CheckedChanged += new System.EventHandler(this.CheckForUpdatesCheckBox_CheckedChanged);
            // 
            // enableDiscordRPCStatusCheckBox
            // 
            this.enableDiscordRPCStatusCheckBox.AutoSize = true;
            this.enableDiscordRPCStatusCheckBox.Location = new System.Drawing.Point(12, 81);
            this.enableDiscordRPCStatusCheckBox.Name = "enableDiscordRPCStatusCheckBox";
            this.enableDiscordRPCStatusCheckBox.Size = new System.Drawing.Size(153, 17);
            this.enableDiscordRPCStatusCheckBox.TabIndex = 4;
            this.enableDiscordRPCStatusCheckBox.Text = "Enable DiscordRPC Status";
            this.enableDiscordRPCStatusCheckBox.UseVisualStyleBackColor = true;
            this.enableDiscordRPCStatusCheckBox.CheckedChanged += new System.EventHandler(this.EnableDiscordRPCStatusCheckBox_CheckedChanged);
            // 
            // Gen2InjectionCheckBox
            // 
            this.Gen2InjectionCheckBox.AutoSize = true;
            this.Gen2InjectionCheckBox.Location = new System.Drawing.Point(12, 12);
            this.Gen2InjectionCheckBox.Name = "Gen2InjectionCheckBox";
            this.Gen2InjectionCheckBox.Size = new System.Drawing.Size(188, 17);
            this.Gen2InjectionCheckBox.TabIndex = 5;
            this.Gen2InjectionCheckBox.Text = "Use Injection Gen2 (C# + WinAPI)";
            this.Gen2InjectionCheckBox.UseVisualStyleBackColor = true;
            this.Gen2InjectionCheckBox.CheckedChanged += new System.EventHandler(this.Gen2InjectionCheckBox_CheckedChanged);
            // 
            // SettingsForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(28)))), ((int)(((byte)(28)))), ((int)(((byte)(28)))));
            this.ClientSize = new System.Drawing.Size(234, 136);
            this.Controls.Add(this.Gen2InjectionCheckBox);
            this.Controls.Add(this.enableDiscordRPCStatusCheckBox);
            this.Controls.Add(this.checkForUpdatesCheckBox);
            this.Controls.Add(this.okButton);
            this.Controls.Add(this.useAlternativeInjectionCheckBox);
            this.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(244)))), ((int)(((byte)(244)))), ((int)(((byte)(244)))));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "SettingsForm";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Settings";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.CheckBox useAlternativeInjectionCheckBox;
        private System.Windows.Forms.Button okButton;
        private System.Windows.Forms.CheckBox checkForUpdatesCheckBox;
        private System.Windows.Forms.CheckBox enableDiscordRPCStatusCheckBox;
        private System.Windows.Forms.CheckBox Gen2InjectionCheckBox;
    }
}