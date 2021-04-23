using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MiljectorHelper
{
    class Program
    {
        public static bool IsAdministrator => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

        [DllImport("MiljectorLib.dll")]
        internal static extern uint Process(string process_name);

        [DllImport("MiljectorLib.dll")]
        internal static extern uint Inject(string process_name, string library);

        static void Main(string[] args)
        {
            if (!IsAdministrator)
            {
                Environment.Exit(250);
            }
            Console.WriteLine($"Injecting \"{args[1]}\" in process \"{args[0]}.exe\"\n-------------------------------------------");
            uint return_val = Inject(args[0] + ".exe", args[1]);
            Console.WriteLine("Success!\nResult: " + return_val + "\n-------------------------------------------");
            Thread.Sleep(1000);
            Environment.Exit((int)return_val);
        }
    }
}
