using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
namespace RAMCollector
{
    public static class DumpIt
    {
        public static void CallDumpIt()
        {
            Process process = new Process();
            string machineName = Environment.MachineName;
            DateTime currentDate = DateTime.Now;

            string filename = machineName + "-" + currentDate.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".raw";

            process.StartInfo = new ProcessStartInfo("DumpIt.exe")
            {
                UseShellExecute = false
            };

            try
            {
                process.Start();
                process.WaitForExit();                
            }
            catch (Win32Exception e)
            {
                Console.WriteLine("Error at DumpIt invoker");
                Console.WriteLine(e.Message);
                //Console.WriteLine("DumpIt.exe not found");
                throw;
            }
        }
    }
}
