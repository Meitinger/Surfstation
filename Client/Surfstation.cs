/* Copyright (C) 2012-2013, Manuel Meitinger
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
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceModel;
using System.Text;
using System.Threading;
using Aufbauwerk.Security.AccessControl;
using Microsoft.Win32;

namespace Aufbauwerk.Surfstation.Client
{
    abstract class Session : ClientBase<ISession>, IDisposable
    {
        public static Session Create(string[] args)
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT: return new WindowsSession(args);
                case PlatformID.Unix: return new GtkSession(args);
                default: throw new PlatformNotSupportedException();
            }
        }

        class GtkSession : Session
        {
            #region Posix definitions

            [DllImport("libc", ExactSpelling = true, SetLastError = true)]
            static extern void kill(int pid, int sig);

            [DllImport("libc", ExactSpelling = true, SetLastError = true)]
            static extern int getpid();

            const int SIGKILL = 9;

            #endregion

            readonly string[] args;

            public GtkSession(string[] args)
            {
                // store the arguments and initialize Gtk
                this.args = args;
                Gtk.Application.Init();
            }

            public override bool CheckPreconditions()
            {
                // we can only continue if at least the shell's command path was provided
                return args != null && args.Length > 0;
            }

            protected override Process CreateShell()
            {
                // execute the program given by the command line
                var psi = new ProcessStartInfo()
                {
                    FileName = args[0],
                    UseShellExecute = false,
                };
                psi.Arguments = args.Skip(1).Aggregate("", (s, c) => s + " \"" + c.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"");
                return Process.Start(psi);
            }

            protected override Rectangle GetDesktopBounds()
            {
                // return the size of the default display's first screen (which is what Mono's CopyFromScreen is using)
                int x, y, width, height, depth;
                Gdk.Display.Default.GetScreen(0).RootWindow.GetGeometry(out x, out y, out width, out height, out depth);
                return new Rectangle(x, y, width, height);
            }

            protected override bool QueryPassword(ref string userName, ref string password, bool passwordIncorrect)
            {
                // show the GNOME password dialog (passwordIncorrect is ignored)
                using (var dlg = new Gnome.PasswordDialog(Program.Settings.Target, null, userName, password, false))
                {
                    var confirmed = dlg.RunAndBlock();
                    dlg.Hide();
                    userName = confirmed ? dlg.Username : null;
                    password = confirmed ? dlg.Password : null;
                    return confirmed;
                }
            }

            protected override void ShowErrorDialog(string msg, bool isFatal)
            {
                // show the error dialog
                using (var dlg = new Gtk.MessageDialog(null, Gtk.DialogFlags.Modal, isFatal ? Gtk.MessageType.Error : Gtk.MessageType.Warning, Gtk.ButtonsType.Ok, null))
                {
                    dlg.Title = Program.Settings.Target;
                    dlg.Text = msg;
                    dlg.Run();
                    dlg.Hide();
                }
            }

            protected override void Shutdown()
            {
                // terminate anything created in our process group
                kill(-getpid(), SIGKILL);
            }
        }

        class WindowsSession : Session
        {
            #region Win32 definitions

            [DllImport("user32", ExactSpelling = true, SetLastError = true)]
            static extern bool ExitWindowsEx([In] uint uFlags, [In] uint dwReason);

            [DllImport("credui", CharSet = CharSet.Auto)]
            static extern int CredUIPromptForCredentials(
                [In, Optional] IntPtr pUiInfo,
                [In] string pszTargetName,
                [In] IntPtr Reserved,
                [In, Optional] uint dwAuthError,
                [In, Out] StringBuilder pszUserName,
                [In] int ulUserNameMaxChars,
                [In, Out] StringBuilder pszPassword,
                [In] int ulPasswordMaxChars,
                [In, Out] ref bool pfSave,
                [In] uint dwFlags);

            const uint EWX_LOGOFF = 0;
            const uint EWX_FORCE = 0x00000004;
            const uint EWX_FORCEIFHUNG = 0x00000010;

            const uint CREDUI_FLAGS_ALWAYS_SHOW_UI = 0x00080;
            const uint CREDUI_FLAGS_DO_NOT_PERSIST = 0x00002;
            const uint CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x40000;
            const uint CREDUI_FLAGS_INCORRECT_PASSWORD = 0x00001;
            const int CREDUI_FLAGS_EXCLUDE_CERTIFICATES = 0x00008;
            const int CREDUI_MAX_PASSWORD_LENGTH = (512 / 2);
            const int CREDUI_MAX_USERNAME_LENGTH = (256 + 1 + 256);
            const int NO_ERROR = 0;
            const int ERROR_CANCELLED = 1223;

            #endregion

            readonly Process currentProcess;
            readonly string shell;
            readonly Mutex mutex;
            readonly bool firstInstace;

            public WindowsSession(string[] args)
            {
                // open and protect the current process
                currentProcess = Process.GetCurrentProcess();
                var security = currentProcess.GetAccessControl(AccessControlSections.Access);
                security.AddAccessRule(new ProcessAccessRule(WindowsIdentity.GetCurrent().User, ProcessRights.Terminate, AccessControlType.Deny));
                currentProcess.SetAccessControl(security);

                // create the single instance mutex
                mutex = new Mutex(false, GetType().GUID.ToString(), out firstInstace);

                // retrieve the path to the shell
                shell = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", null) as string;
                if (string.IsNullOrWhiteSpace(shell))
                    shell = "explorer.exe";

                // enable visual styles
                System.Windows.Forms.Application.EnableVisualStyles();
            }

            private bool IsSameFileName(Process p)
            {
                // try to compare the main module file name
                try { return p.MainModule.FileName == currentProcess.MainModule.FileName; }
                catch (Win32Exception) { return false; }
            }

            public override bool CheckPreconditions()
            {
                // quit if another instance is already running
                if (!firstInstace)
                    return false;
#if !DEBUG
                // if the current user is an admin, simply start the shell
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    {
                        CreateShell();
                        return false;
                    }
                }
#endif
                return true;
            }

            protected override Process CreateShell()
            {
                // start the system shell (usually explorer.exe)
                return Process.Start(new ProcessStartInfo() { UseShellExecute = false, FileName = shell });
            }

            protected override Rectangle GetDesktopBounds()
            {
                // retrieve the entire desktop area
                return System.Windows.Forms.SystemInformation.VirtualScreen;
            }

            protected override bool QueryPassword(ref string userName, ref string password, bool passwordIncorrect)
            {
                // initialize the variables
                var userNameBuffer = new StringBuilder(userName, CREDUI_MAX_USERNAME_LENGTH + 1);
                var passwordBuffer = new StringBuilder(password, CREDUI_MAX_PASSWORD_LENGTH + 1);
                var save = false;
                var flags = CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_EXCLUDE_CERTIFICATES;
                if (passwordIncorrect)
                    flags |= CREDUI_FLAGS_INCORRECT_PASSWORD;

                // query for credentials and return the user name and password
                var result = CredUIPromptForCredentials(IntPtr.Zero, Program.Settings.Target, IntPtr.Zero, 0, userNameBuffer, userNameBuffer.Capacity, passwordBuffer, passwordBuffer.Capacity, ref save, flags);
                switch (result)
                {
                    case NO_ERROR:
                        userName = userNameBuffer.ToString();
                        password = passwordBuffer.ToString();
                        return true;
                    case ERROR_CANCELLED:
                        userName = null;
                        password = null;
                        return false;
                    default: throw new Win32Exception(result);
                }
            }

            protected override void ShowErrorDialog(string msg, bool isFatal)
            {
                // show the error dialog
                System.Windows.Forms.MessageBox.Show(msg, Program.Settings.Target, System.Windows.Forms.MessageBoxButtons.OK, isFatal ? System.Windows.Forms.MessageBoxIcon.Error : System.Windows.Forms.MessageBoxIcon.Warning);
            }

            protected override void Shutdown()
            {
#if !DEBUG
                // force a logoff
                ExitWindowsEx(EWX_LOGOFF | EWX_FORCE | EWX_FORCEIFHUNG, 0);
#endif
            }
        }

        private bool disposed = false;

        protected Session()
        {
            // shutdown on any unhandled exceptions
            AppDomain.CurrentDomain.UnhandledException += (s, e) => { if (e.IsTerminating) Shutdown(); };
        }

        ~Session()
        {
            // implicitly dispose the session
            Dispose(false);
        }

        void IDisposable.Dispose()
        {
            // explicitly dispose the session
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            // if not disposed yet shutdown the session
            if (!disposed)
            {
                Shutdown();
                disposed = true;
            }
        }

        public abstract bool CheckPreconditions();

        protected abstract Process CreateShell();

        protected abstract Rectangle GetDesktopBounds();

        protected abstract bool QueryPassword(ref string userName, ref string password, bool passwordIncorrect);

        protected abstract void ShowErrorDialog(string msg, bool isFatal);

        protected abstract void Shutdown();

        public void ReportError(Exception e)
        {
#if DEBUG
            var msg = e is FaultException ? e.Message : e.ToString();
#else
            var msg = e is FaultException ? (((FaultException)e).Code.IsSenderFault ? new ApplicationException().Message : new SystemException().Message) : e.Message;
#endif
            ShowErrorDialog(msg, !(e is FaultException));
        }

        public void Run()
        {
            var userName = string.Empty;
            var password = string.Empty;

            // initial query for credentials
            if (!QueryPassword(ref userName, ref password, false))
                return;

            // try to login and ask for credentials again on failure
            while (!Channel.Login(userName, password, Environment.MachineName))
                if (!QueryPassword(ref userName, ref password, true))
                    return;

            // start the actual shell
            using (var shell = CreateShell())
            using (var buffer = new MemoryStream())
            {
            CreateScreenBuffer:
                // create the screenshot bitmap using the current combined resolution
                var bounds = GetDesktopBounds();
                using (var bitmap = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format24bppRgb))
                {
                    // send screenshots and continuation requests as long as the shell is running
                    while (!shell.HasExited)
                    {
                        // make a screenshot
                        using (var gc = Graphics.FromImage(bitmap))
                            gc.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size);

                        // serialize the screenshot and request a session continuation
                        buffer.SetLength(0);
                        bitmap.Save(buffer, ImageFormat.Png);
                        buffer.Seek(0, SeekOrigin.Begin);
                        if (!Channel.Continue(buffer))
                            break;

                        // wait a little
                        Thread.Sleep(Program.Settings.Interval);

                        // recreate the screen bitmap if the resolution has changed
                        if (bounds != GetDesktopBounds())
                            goto CreateScreenBuffer;
                    }
                }
            }

            // logout
            Channel.Logout();
        }
    }
}
