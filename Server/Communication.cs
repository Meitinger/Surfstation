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
using System.IO;
using System.ServiceModel;

namespace Aufbauwerk.Surfstation.Server
{
    [ServiceContract(Namespace = "http://schemas.aufbauwerk.com/surfstation/session", SessionMode = SessionMode.Required)]
    interface ISession
    {
        [OperationContract(IsInitiating = true)]
        [FaultContract(typeof(ArgumentNullException))]
        [FaultContract(typeof(ObjectDisposedException))]
        [FaultContract(typeof(InvalidOperationException))]
        bool Login(string userName, string password, string machineName);

        [OperationContract]
        [FaultContract(typeof(ArgumentNullException))]
        [FaultContract(typeof(ObjectDisposedException))]
        [FaultContract(typeof(InvalidOperationException))]
        bool Continue(Stream image);

        [OperationContract(IsTerminating = true)]
        [FaultContract(typeof(ObjectDisposedException))]
        [FaultContract(typeof(InvalidOperationException))]
        void Logout();
    }
}
