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
            ServiceApplication.Run();
        }
    }
}
