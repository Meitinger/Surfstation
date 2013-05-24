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
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceModel;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Aufbauwerk.Surfstation.Client
{
    class Session : ClientBase<ISession>
    {
        [DllImport("Credui.dll", CharSet = CharSet.Auto)]
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

        const uint CREDUI_FLAGS_ALWAYS_SHOW_UI = 0x00080;
        const uint CREDUI_FLAGS_DO_NOT_PERSIST = 0x00002;
        const uint CREDUI_FLAGS_GENERIC_CREDENTIALS = 0x40000;
        const uint CREDUI_FLAGS_INCORRECT_PASSWORD = 0x00001;
        const int CREDUI_FLAGS_EXCLUDE_CERTIFICATES = 0x00008;
        const int CREDUI_MAX_PASSWORD_LENGTH = (512 / 2);
        const int CREDUI_MAX_USERNAME_LENGTH = (256 + 1 + 256);
        const int NO_ERROR = 0;
        const int ERROR_CANCELLED = 1223;

        public void Run()
        {
            // initialize the variables
            var userName = new StringBuilder(CREDUI_MAX_USERNAME_LENGTH + 1);
            var password = new StringBuilder(CREDUI_MAX_PASSWORD_LENGTH + 1);
            var save = false;
            var flags = CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_EXCLUDE_CERTIFICATES;

        QueryCredentials:
            // show the credentials dialog and logon the user
            var result = CredUIPromptForCredentials(IntPtr.Zero, Program.Settings.Target, IntPtr.Zero, 0, userName, userName.Capacity, password, password.Capacity, ref save, flags);
            switch (result)
            {
                case NO_ERROR:
                    flags |= CREDUI_FLAGS_INCORRECT_PASSWORD;
                    if (userName.Length == 0 || password.Length == 0 || !Channel.Login(userName.ToString(), password.ToString(), Environment.MachineName))
                        goto QueryCredentials;
                    break;
                case ERROR_CANCELLED:
                    userName.Length = 0;
                    password.Length = 0;
                    flags &= ~CREDUI_FLAGS_INCORRECT_PASSWORD;
                    goto QueryCredentials;
                default: throw new Win32Exception(result);
            }

            // start the actual shell
            using (var shell = Process.Start(new ProcessStartInfo() { UseShellExecute = false, FileName = Program.Settings.Shell }))
            {
            CreateScreenBuffer:
                // create the screenshot bitmap buffer with the current primary screen resolution
                var bounds = Screen.PrimaryScreen.Bounds;
                using (var bitmap = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format24bppRgb))
                {
                    // send screenshots and continuation requests as long as the shell is running
                    while (!shell.HasExited)
                    {
                        // make a screenshot
                        using (var gc = Graphics.FromImage(bitmap))
                            gc.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size);

                        // serialize the screenshot to a byte array and request a session continuation
                        using (var buffer = new MemoryStream())
                        {
                            bitmap.Save(buffer, ImageFormat.Png);
                            buffer.Seek(0, SeekOrigin.Begin);
                            if (!Channel.Continue(buffer))
                                break;
                        }

                        // wait a little
                        Thread.Sleep(Program.Settings.Interval);

                        // recreate the screen buffer if the resolution has changed
                        if (bounds != Screen.PrimaryScreen.Bounds)
                            goto CreateScreenBuffer;
                    }
                }
            }

            // logout
            Channel.Logout();
        }
    }
}
