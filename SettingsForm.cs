using Miljector.Properties;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Miljector
{
    public partial class SettingsForm : Form
    {
        public SettingsForm()
        {
            InitializeComponent();
            if (Settings.Default.UseGen2Injection)
                Gen2InjectionCheckBox.Checked = true;
            if (Settings.Default.UseAlternativeInjection)
                useAlternativeInjectionCheckBox.Checked = true;
            if (Settings.Default.CheckForUpdates)
                checkForUpdatesCheckBox.Checked = true;
            if (Settings.Default.EnableDiscordRPC)
                enableDiscordRPCStatusCheckBox.Checked = true;
        }

        private void OkButton_Click(object sender, EventArgs e)
        {
            Settings.Default.Save();
            Close();
        }

        private void Gen2InjectionCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (Gen2InjectionCheckBox.Checked)
                Settings.Default.UseGen2Injection = true;
            else
                Settings.Default.UseGen2Injection = false;
        }

        private void UseAlternativeInjectionCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (useAlternativeInjectionCheckBox.Checked)
                Settings.Default.UseAlternativeInjection = true;
            else
                Settings.Default.UseAlternativeInjection = false;
        }

        private void CheckForUpdatesCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (checkForUpdatesCheckBox.Checked)
                Settings.Default.CheckForUpdates = true;
            else
                Settings.Default.CheckForUpdates = false;
        }

        private void EnableDiscordRPCStatusCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (enableDiscordRPCStatusCheckBox.Checked)
                Settings.Default.EnableDiscordRPC = true;
            else
                Settings.Default.EnableDiscordRPC = false;
        }
    }
}
