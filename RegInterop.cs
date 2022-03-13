using System;
using System.Runtime.InteropServices;
namespace ZP.PowerShell.WinFTAManager
{
    public class RegInterop
    {
        [DllImport("shell32.dll")] 
        private static extern int SHChangeNotify(
            int eventId,
            int flags,
            IntPtr item1,
            IntPtr item2);
        public static void Refresh()
        {
            SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegOpenKeyEx(
            UIntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            out UIntPtr hkResult);
        [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
        private static extern uint RegDeleteKey(
            UIntPtr hKey,
            string subKey);
        public static void DeleteKey(string key)
        {
            UIntPtr hKey = UIntPtr.Zero;
            RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
            RegDeleteKey((UIntPtr)0x80000001u, key);
        }
    }
}