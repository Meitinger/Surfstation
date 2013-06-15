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
using Aufbauwerk.Surfstation.Client.Properties;

namespace Aufbauwerk.Surfstation.Client
{
    static class Program
    {
        internal static Settings Settings
        {
            get { return Settings.Default; }
        }

        [STAThread]
        static void Main(string[] args)
        {
            // create the session
            using (var session = Session.Create(args))
            {
                try
                {
                    // ensure that all preconditions are met
                    if (!session.CheckPreconditions())
                        return;

                    // open the session and run it
                    session.Open();
                    session.Run();
                    session.Close();
                }
                catch (Exception e)
                {
                    // abort the session and report the error
                    session.Abort();
                    session.ReportError(e);
                }
            }
        }
    }
}
