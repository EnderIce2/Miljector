using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static Miljector.InjectHelper;

namespace Miljector
{
    public partial class MainForm : Form
    {
        public static string dllpath = null;
        public static string processname = null;
        readonly LoadingForm loadingForm = new LoadingForm();
        public MainForm()
        {
            InitializeComponent();
        }

        private void AboutLinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            new AboutForm().ShowDialog();
        }

        private async void RefreshLinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            loadingForm.Show();
            await Task.Run(() =>
            {
                browseDLLButton.Invoke(new Action(() => browseDLLButton.Enabled = false));
                injectButton.Invoke(new Action(() => injectButton.Enabled = false));
                processComboBox.Invoke(new Action(() => processComboBox.Enabled = false));
                refreshLinkLabel.Invoke(new Action(() => refreshLinkLabel.Enabled = false));
                processComboBox.Invoke(new Action(() => processComboBox.Items.Clear()));
                Process[] processes = Process.GetProcesses();
                foreach (Process p in processes)
                {
                    if (p.MainWindowHandle == IntPtr.Zero)
                    {
                        continue;
                    }
                    if (!string.IsNullOrEmpty(p.ProcessName))
                    {
                        processComboBox.Invoke(new Action(() =>
                        {
                            /* string x32or64 = "(x??)";
                            try
                            {
                                if (IsWin64Emulator(p))
                                    x32or64 = "(x64)";
                                else
                                    x32or64 = "(x32)";
                            }
                            catch (Exception) { }
                            DropDownItem drop = new DropDownItem
                            {
                                Value = p.ProcessName + $" {x32or64}"
                            };
                             try
                             {
                                 Icon ico = Icon.ExtractAssociatedIcon(p.MainModule.FileName);
                                drop.Image = ResizeImage(ico.ToBitmap(), 16, 16);
                            }
                             catch (Exception)
                             {
                                // TODO: implement
                            } */
                            processComboBox.Items.Add(p.ProcessName);
                        }));
                    }
                }
                browseDLLButton.Invoke(new Action(() => browseDLLButton.Enabled = true));
                injectButton.Invoke(new Action(() => injectButton.Enabled = true));
                processComboBox.Invoke(new Action(() => processComboBox.Enabled = true));
                refreshLinkLabel.Invoke(new Action(() => refreshLinkLabel.Enabled = true));
            });
            loadingForm.Hide();
        }

        private void ProcessComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            processLabel.Text = processLabel.Tag + processComboBox.SelectedItem.ToString();
            //processname = processComboBox.SelectedItem.ToString().Replace(" (x64)", "").Replace(" (x32)", "").Replace(" (x??)", "");
            Process[] processes = Process.GetProcessesByName(processComboBox.SelectedItem.ToString()); //.Replace(" (x64)", "").Replace(" (x32)", "").Replace(" (x??)", ""));
            foreach (Process process in processes)
            {
                try
                {
                    Icon ico = Icon.ExtractAssociatedIcon(process.MainModule.FileName);
                    processPictureBox.Image = ico.ToBitmap();
                    /* try
                    {

                        if (IsWin64Emulator(process))
                            procArchImage.Image = Resources._64_48px;
                        else
                            procArchImage.Image = Resources._32_48px;
                    }
                    catch (Exception)
                    {
                        procArchImage.Image = Resources.question_mark_48px;
                    } */
                }
                catch (Exception)
                {
                    // TODO: implement
                }
                processname = process.ProcessName;
            }
        }

        private void BrowseDLLButton_Click(object sender, EventArgs e)
        {
            DialogResult result = DLLFileDialog.ShowDialog();
            if (result == DialogResult.OK)
            {
                try
                {
                    dllpath = DLLFileDialog.FileName;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Internal error!\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    dllpath = null;
                }
            }
        }

        private async void InjectButton_Click(object sender, EventArgs e)
        {
            if (processname == null)
            {
                MessageBox.Show("Please select the process!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!File.Exists(dllpath))
            {
                if (dllpath == null)
                {
                    MessageBox.Show("Please select the DLL!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                MessageBox.Show($"The path '{dllpath}' is invalid!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            infoLabel.Text = "Please wait...";
            try
            {
                if (processComboBox.SelectedItem.ToString() == null)
                    return;
            }
            catch (Exception)
            {
                infoLabel.Text = "No process selected!";
                return;
            }
            await Task.Run(() =>
            {
                infoLabel.Invoke(new Action(() => infoLabel.Text = AttachProcess(dllpath)));
            });
        }

        bool updateClick = false;
        Root github_update_data;
        private async void MainForm_Load(object sender, EventArgs e)
        {
            loadingForm.Show();
            /* if (IsMono())
            {
                MessageBox.Show("Platform not supported!");
            } */
            IsWine();

            await Task.Run(() =>
            {
                string[] result = ((string)infoLabel.Tag).Split(new string[] { " {|} " }, StringSplitOptions.None);
                // 0 = up to date | 1 = out of date

                WebClient client = new WebClient();

                client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");

                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                try
                {
                    Stream data = client.OpenRead("https://api.github.com/repos/EnderIce2/Miljector/releases");
                    StreamReader reader = new StreamReader(data);
                    string s = reader.ReadToEnd();
                    // https://api.github.com/repos/EnderIce2/Miljector/releases
                    Root responsed_data = JsonConvert.DeserializeObject<Root>(s.Substring(1, s.Length - 2));
                    github_update_data = responsed_data;
                    // TODO: implement a better way to check for updates
                    Version github_version = new Version(responsed_data.tag_name.Replace("v", ""));
                    Version current_version = new Version(Application.ProductVersion);
                    if (github_version != current_version)
                    {
                        infoLabel.Invoke(new Action(() => infoLabel.Text = result[1]));
                        updateClick = true;
                    }
                    else
                        infoLabel.Invoke(new Action(() => infoLabel.Text = result[0]));
                }
                catch (Exception ex)
                {
                    infoLabel.Invoke(new Action(() => infoLabel.Text = $"Error checking for update: {ex.Message}"));
                }
            });

            await Task.Run(() =>
        {
            browseDLLButton.Invoke(new Action(() => browseDLLButton.Enabled = false));
            injectButton.Invoke(new Action(() => injectButton.Enabled = false));
            processComboBox.Invoke(new Action(() => processComboBox.Enabled = false));
            refreshLinkLabel.Invoke(new Action(() => refreshLinkLabel.Enabled = false));
            processComboBox.Invoke(new Action(() => processComboBox.Items.Clear()));
            Process[] processes = Process.GetProcesses();
            foreach (Process p in processes)
            {
                if (p.MainWindowHandle == IntPtr.Zero)
                {
                    continue;
                }
                if (!string.IsNullOrEmpty(p.ProcessName))
                {
                    processComboBox.Invoke(new Action(() =>
                    {
                        /* string x32or64 = "(x??)";
                        try
                        {
                            if (IsWin64Emulator(p))
                                x32or64 = "(x64)";
                            else
                                x32or64 = "(x32)";
                        }
                        catch (Exception) { }
                        DropDownItem drop = new DropDownItem
                        {
                            Value = p.ProcessName + $" {x32or64}"
                        };
                        try
                        {
                            Icon ico = Icon.ExtractAssociatedIcon(p.MainModule.FileName);
                            //drop.Image = ResizeImage(ico.ToBitmap(), 16, 16);
                        }
                        catch (Exception)
                        {
                            // TODO: implement
                        } */
                        processComboBox.Items.Add(p.ProcessName);
                    }));
                }
            }
            browseDLLButton.Invoke(new Action(() => browseDLLButton.Enabled = true));
            injectButton.Invoke(new Action(() => injectButton.Enabled = true));
            processComboBox.Invoke(new Action(() => processComboBox.Enabled = true));
            refreshLinkLabel.Invoke(new Action(() => refreshLinkLabel.Enabled = true));
        });
            loadingForm.Hide();
        }
        private void InfoLabel_Click(object sender, EventArgs e)
        {
            if (updateClick)
                Process.Start(github_update_data.html_url);
        }
    }
}