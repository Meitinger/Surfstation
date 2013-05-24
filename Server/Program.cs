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

using System.Data.OleDb;
using System.Diagnostics;
using Aufbauwerk.ServiceProcess;
using Aufbauwerk.Surfstation.Server.Properties;

namespace Aufbauwerk.Surfstation.Server
{
    static class Program
    {
        internal static Settings Settings
        {
            get { return Settings.Default; }
        }

        static void Main()
        {
            // hook up all event handlers and run the service application
            ServiceApplication.Start += Session.Start;
            ServiceApplication.Start += RadiusServer.Start;
            ServiceApplication.Stop += Session.Stop;
            ServiceApplication.Stop += RadiusServer.Stop;
            ServiceApplication.Exception += FilterException;
            ServiceApplication.Run();
        }

        static void FilterException(object sender, ServiceExceptionEventArgs e)
        {
            // ingore (log-only) all database exception that occur when the server/file is not available
            if (e.Exception is OleDbException)
            {
                var ex = (OleDbException)e.Exception;
                if (ex.Errors.Count == 1 && (ex.Errors[0].SQLState == "3024" || ex.Errors[0].SQLState == "3044"))
                {
                    ServiceApplication.LogEvent(EventLogEntryType.Warning, ex.Errors[0].Message);
                    e.Cancel = true;
                }
            }
        }
    }
}
