/* Copyright (C) 2012, Manuel Meitinger
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceModel;
using System.Windows.Forms;
using Aufbauwerk.Security.AccessControl;
using Aufbauwerk.Surfstation.Client.Properties;

namespace Aufbauwerk.Surfstation.Client
{
    static class Program
    {
        internal static Settings Settings
        {
            get { return Settings.Default; }
        }

        [DllImport("User32.dll", ExactSpelling = true, SetLastError = true)]
        static extern bool ExitWindowsEx(
            [In] uint uFlags,
            [In] uint dwReason);

        [DllImport("User32.dll", ExactSpelling = true)]
        static extern bool SetForegroundWindow([In] IntPtr hWnd);

        const uint EWX_LOGOFF = 0;
        const uint EWX_FORCE = 0x00000004;
        const uint EWX_FORCEIFHUNG = 0x00000010;

        [STAThread]
        static void Main()
        {
            // quit if another instance is already running
            using (var currentProcess = Process.GetCurrentProcess())
            {
                var otherProcess = (from p in Process.GetProcesses() where p.Id != currentProcess.Id && p.SessionId == currentProcess.SessionId && string.Equals(p.ProcessName, currentProcess.ProcessName, StringComparison.OrdinalIgnoreCase) && string.Equals(p.MainModule.FileName, currentProcess.MainModule.FileName, StringComparison.OrdinalIgnoreCase) select p).FirstOrDefault();
                if (otherProcess != null)
                {
                    SetForegroundWindow(otherProcess.MainWindowHandle);
                    return;
                }
            }

#if !DEBUG
            // if the current user is an admin, simply start the shell
            using (var identity = WindowsIdentity.GetCurrent())
            {
                if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                {
                    using (var shell = Process.Start(new ProcessStartInfo() { UseShellExecute = false, FileName = Settings.Shell }))
                        shell.WaitForExit();
                    return;
                }
            }

            // whatever happens, always forcefully logoff at the end
            System.Runtime.CompilerServices.RuntimeHelpers.PrepareConstrainedRegions();
            try
#endif
            {
                // enable visual styles and protect the process
                Application.EnableVisualStyles();
                using (var process = Process.GetCurrentProcess())
                {
                    var security = process.GetAccessControl(AccessControlSections.Access);
                    security.AddAccessRule(new ProcessAccessRule(WindowsIdentity.GetCurrent().User, ProcessRights.Terminate, AccessControlType.Deny));
                    process.SetAccessControl(security);
                }

                // create the session and run the rest of the program
                var session = new Session();
                try
                {
                    session.Open();
                    session.Run();
                    session.Close();
                }
                catch (FaultException e)
                {
                    session.Abort();
#if DEBUG
                    MessageBox.Show(e.Message, Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
#else
                    MessageBox.Show(e.Code.IsSenderFault ? new ApplicationException().Message : new SystemException().Message, Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
#endif
                }
                catch (Exception e)
                {
                    session.Abort();
#if DEBUG
                    MessageBox.Show(e.ToString(), Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Error);
#else
                    MessageBox.Show(e.Message, Application.ProductName, MessageBoxButtons.OK, MessageBoxIcon.Error);
#endif
                }
            }
#if !DEBUG
            finally
            {
                ExitWindowsEx(EWX_LOGOFF | EWX_FORCE | EWX_FORCEIFHUNG, 0);
            }
#endif
        }
    }
}
