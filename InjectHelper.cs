using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Miljector
{
    [SuppressUnmanagedCodeSecurity]
    public static class InjectHelper
    {
        internal static class NativeMethods
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern int CloseHandle(IntPtr hObject);
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr GetModuleHandle(string lpModuleName);
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesWritten);
            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress,
                IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);
            [DllImport("ntdll.dll")]
            internal static extern string Wine_get_version();
        }

        private static readonly IntPtr INTPTR_ZERO = (IntPtr)0;
        private static int processId;
        public static int pid;

        #region Injection
        public static string AttachProcess(string patch)
        {
            Process[] processes = Process.GetProcessesByName(MainForm.processname);
            if (processes.Length == 0)
            {
                return "Process Not Found (0x1)";
            }
            foreach (Process process in processes)
            {
                if (process.MainWindowHandle == IntPtr.Zero)
                {
                    return "This is background process! (0x2)";
                }
                processId = process.Id;
                pid = processId;
                return InjectUsingID(processId, patch);
            }
            return "Unknown error (0x3)";
        }

        static IntPtr error_code = INTPTR_ZERO;
        static string error_where = "unknown";
        public static string InjectUsingID(int id, string sDllPath)
        {
            if (!File.Exists(sDllPath))
            {
                return "DLL Not Found (0x4)";
            }
            uint _proccessId = (uint)id;
            if (_proccessId == 0)
            {
                return "Process Not Found (0x5)";
            }
            if (!InjectLibrary(_proccessId, sDllPath))
            {
                if (error_code == INTPTR_ZERO && error_where == "OpenProcess")
                    MessageBox.Show("OpenProcess returned 0, something went wrong...\nYou can try again but this time run as administrator the injector!", "Injection Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return $"Injection Failed ({error_code} at {error_where})";
            }
            return $"Success ({MainForm.processname})";
        }

        public static bool InjectLibrary(uint pToBeInjected, string sDllPath)
        {
            IntPtr hndProcess = NativeMethods.OpenProcess(0x2 | 0x8 | 0x10 | 0x20 | 0x400, 1, pToBeInjected);
            Debug.WriteLine("OpenProcess: " + hndProcess);
            if (hndProcess == INTPTR_ZERO)
            {
                error_where = "OpenProcess";
                error_code = hndProcess;
                return false;
            }
            IntPtr lpLLAddress = NativeMethods.GetProcAddress(NativeMethods.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            Debug.WriteLine("GetProcAddress: " + lpLLAddress);
            if (lpLLAddress == INTPTR_ZERO)
            {
                error_where = "GetProcAddress";
                error_code = lpLLAddress;
                return false;
            }
            IntPtr lpAddress = NativeMethods.VirtualAllocEx(hndProcess, (IntPtr)null, (IntPtr)sDllPath.Length, 0x1000 | 0x2000, 0X40);
            Debug.WriteLine("VirtualAllocEx: " + lpAddress);
            if (lpAddress == INTPTR_ZERO)
            {
                error_where = "VirtualAllocEx";
                error_code = lpAddress;
                return false;
            }
            byte[] bytes = Encoding.ASCII.GetBytes(sDllPath);
            int res1 = NativeMethods.WriteProcessMemory(hndProcess, lpAddress, bytes, (uint)bytes.Length, 0);
            Debug.WriteLine("WriteProcessMemory: " + res1);
            if (res1 == 0)
            {
                error_where = "WriteProcessMemory";
                error_code = (IntPtr)res1;
                return false;
            }
            IntPtr res2 = NativeMethods.CreateRemoteThread(hndProcess, (IntPtr)null, INTPTR_ZERO, lpLLAddress, lpAddress, 0, (IntPtr)null);
            Debug.WriteLine("CreateRemoteThread: " + res2);
            if (res2 == INTPTR_ZERO)
            {
                error_where = "CreateRemoteThread";
                error_code = res2;
                return false;
            }
            NativeMethods.CloseHandle(hndProcess);
            return true;
        }
        #endregion

        #region Compatibility
        public static string wine_name;
        public static bool IsWine()
        {
            try
            {
                wine_name = NativeMethods.Wine_get_version();
                Console.WriteLine("---------------------------------------------------------------------------------------------");
                Console.WriteLine($"Running under {wine_name}! Please report any problems that may occur while using it!");
                Console.WriteLine("---------------------------------------------------------------------------------------------");
            }
            catch (Exception) { return false; }
            return true;
        }
        public static bool IsMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }
        #endregion

        #region Detect64Bit
        public static bool IsWin64Emulator(Process process)
        {
            if (IntPtr.Size == 4)
                return false;
            else if (IntPtr.Size == 8)
                if ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
                    return NativeMethods.IsWow64Process(process.Handle, out bool retVal) && retVal;
                return false;
        }
        #endregion

        #region Image
        public static Bitmap ResizeImage(Image image, int width, int height)
        {
            var destRect = new Rectangle(0, 0, width, height);
            var destImage = new Bitmap(width, height);
            destImage.SetResolution(image.HorizontalResolution, image.VerticalResolution);
            using (var graphics = Graphics.FromImage(destImage))
            {
                graphics.CompositingMode = CompositingMode.SourceCopy;
                graphics.CompositingQuality = CompositingQuality.HighSpeed;
                graphics.InterpolationMode = InterpolationMode.Low;
                graphics.SmoothingMode = SmoothingMode.HighSpeed;
                graphics.PixelOffsetMode = PixelOffsetMode.HighSpeed;

                using (var wrapMode = new ImageAttributes())
                {
                    wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                    graphics.DrawImage(image, destRect, 0, 0, image.Width, image.Height, GraphicsUnit.Pixel, wrapMode);
                }
            }
            return destImage;
        }
        #endregion

        #region Update
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE1006:Naming Styles", Justification = "<Pending>")]
        public class Root
        {
            [JsonProperty("html_url")]
            public string html_url { get; set; }
            [JsonProperty("tag_name")]
            public string tag_name { get; set; }
        }

        #endregion
    }
}