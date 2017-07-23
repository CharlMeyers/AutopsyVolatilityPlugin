using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace RAMCollector
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This program will call another program called 'Dumpit' to collect a ram dump of this computer,"+
            "then it will create a hash for use in validating the integrity of the memory dump later.");

            Console.Write("\nOnce you see ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("'success'");
            Console.ResetColor();
            Console.Write(" in 'Dumpit' press any key to close 'Dumpit'\n");
            Console.Write("\nPress (y) if you understand, (n) otherwise: ");

            char option = Char.ToLower(Console.ReadKey().KeyChar);
            Console.WriteLine("");
            while (option != 'y' && option != 'n') {
                Console.Write("Press (y) if you understand, (n) otherwise: ");
                option = Char.ToLower(Console.ReadKey().KeyChar);
                Console.WriteLine("");
            }
            
            if (Char.ToLower(option) == 'y')
            {
                try
                {
                    Console.WriteLine("Starting 'Dumpit'\n");
                    DumpIt.CallDumpIt();

                    string filename = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.raw").FirstOrDefault();

                    Console.WriteLine("");

                    HashCalaculator.CalculateHash(filename);
                }
                catch (Exception e)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("An error occured, gracefully exiting. The error message is:\n");
                    Console.WriteLine(e.Message);
                    Console.ResetColor();
                }
            }
            else
                Console.WriteLine("Thank you for trying this program");

            Console.Write("\nPress any key to continue...");
            Console.ReadKey();
        }
    }
}
