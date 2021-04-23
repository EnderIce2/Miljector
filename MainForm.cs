using DiscordRPC;
using DiscordRPC.Logging;
using Miljector.Properties;
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
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static Miljector.InjectHelper;

namespace Miljector
{
    public partial class MainForm : Form
    {
        // TODO: 32 and 64 bit manually switching of this application
        public static string dllpath;
        public static string processname;
        readonly LoadingForm loadingForm = new LoadingForm();
        public MainForm()
        {
            InitializeComponent();
        }

        private void AboutLinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            new AboutForm().ShowDialog();
        }

        private void SettingsLinkLabel_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            new SettingsForm().ShowDialog();
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
                aboutLinkLabel.Invoke(new Action(() => aboutLinkLabel.Enabled = false));
                settingsLinkLabel.Invoke(new Action(() => settingsLinkLabel.Enabled = false));
                infoLabel.Invoke(new Action(() => infoLabel.Enabled = false));
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
                aboutLinkLabel.Invoke(new Action(() => aboutLinkLabel.Enabled = true));
                settingsLinkLabel.Invoke(new Action(() => settingsLinkLabel.Enabled = true));
                infoLabel.Invoke(new Action(() => infoLabel.Enabled = true));
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
                try
                {
                    if (Settings.Default.UseAlternativeInjection)
                    {
                        Process helper = new Process();
                        helper.StartInfo.FileName = "MiljectorHelper.exe";
                        helper.StartInfo.Arguments = "\"" + processname + "\" \"" + dllpath;
                        helper.StartInfo.Verb = "runas";
                        helper.StartInfo.WindowStyle = ProcessWindowStyle.Normal;
                        helper.Start();
                        helper.WaitForExit();
                        Thread.Sleep(200);
                        infoLabel.Invoke(new Action(() => infoLabel.Text = helper.ExitCode.ToString()));
                    }
                    else
                        infoLabel.Invoke(new Action(() => infoLabel.Text = AttachProcess(dllpath)));
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                    infoLabel.Invoke(new Action(() => infoLabel.Text = "Error: " + ex.Message));
                }
            });
        }

        bool updateClick = false;
        Root github_update_data;
        public DiscordRpcClient client;
        private async void MainForm_Load(object sender_, EventArgs e_)
        {
            loadingForm.Show();
            /* if (IsMono())
            {
                MessageBox.Show("Platform not supported!");
            } */
            await Task.Run(() =>
            {
                browseDLLButton.Invoke(new Action(() => browseDLLButton.Enabled = false));
                injectButton.Invoke(new Action(() => injectButton.Enabled = false));
                processComboBox.Invoke(new Action(() => processComboBox.Enabled = false));
                refreshLinkLabel.Invoke(new Action(() => refreshLinkLabel.Enabled = false));
                aboutLinkLabel.Invoke(new Action(() => aboutLinkLabel.Enabled = false));
                settingsLinkLabel.Invoke(new Action(() => settingsLinkLabel.Enabled = false));
                infoLabel.Invoke(new Action(() => infoLabel.Enabled = false));
                processComboBox.Invoke(new Action(() => processComboBox.Items.Clear()));

                if (!IsWine())
                {
                    if (Settings.Default.EnableDiscordRPC)
                    {
                        client = new DiscordRpcClient("834927430145277992")
                        {
                            Logger = new ConsoleLogger() { Level = LogLevel.Warning }
                        };
                        client.OnReady += (sender, e) =>
                        {
                            Console.WriteLine("-> Ready from user {0}", e.User.Username);
                        };
                        client.OnPresenceUpdate += (sender, e) =>
                        {
                            Console.WriteLine("-> Update {0}", e.Presence);
                        };
                        client.Initialize();
                        client.SetPresence(new RichPresence()
                        {
                            Details = "v" + Application.ProductVersion,
                            State = "https://github.com/EnderIce2/Miljector",
                            Assets = new Assets()
                            {
                                LargeImageKey = "image_large",
                                LargeImageText = "Miljector v" + Application.ProductVersion,
                                SmallImageKey = "image_small",
                                SmallImageText = "EnderIce2"
                            }
                        });
                    }
                }

                if (Settings.Default.CheckForUpdates)
                {
                    // 0 = up to date | 1 = out of date
                    string[] result = ((string)infoLabel.Tag).Split(new string[] { " {|} " }, StringSplitOptions.None);
                    WebClient client = new WebClient();
                    client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");
                    ServicePointManager.Expect100Continue = true;
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    try
                    {
                        Stream data = client.OpenRead("https://api.github.com/repos/EnderIce2/Miljector/releases");
                        StreamReader reader = new StreamReader(data);
                        string s = reader.ReadToEnd();
                        Debug.WriteLine("RESULT:\n" + s);
                        // https://api.github.com/repos/EnderIce2/Miljector/releases
                        List<Root> responsed_data = JsonConvert.DeserializeObject<List<Root>>(s);
                        github_update_data = responsed_data[0];
                        // TODO: implement a better way to check for updates
                        Version github_version = new Version(responsed_data[0].tag_name.Replace("v", ""));
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
                        Debug.WriteLine(ex);
                    }
                }

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
                aboutLinkLabel.Invoke(new Action(() => aboutLinkLabel.Enabled = true));
                settingsLinkLabel.Invoke(new Action(() => settingsLinkLabel.Enabled = true));
                infoLabel.Invoke(new Action(() => infoLabel.Enabled = true));
            });
            loadingForm.Hide();
        }
        private void InfoLabel_Click(object sender, EventArgs e)
        {
            if (updateClick)
                Process.Start(github_update_data.html_url);
        }

        private void MainForm_FormClosed(object sender, FormClosedEventArgs e)
        {
            try
            {
                client.Dispose();
            }
            catch (NullReferenceException)
            { }
        }
    }
}