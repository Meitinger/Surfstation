/* Copyright (C) 2012-2014, Manuel Meitinger
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
using System.Data.OleDb;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Aufbauwerk.Net.Radius;
using Aufbauwerk.ServiceProcess;

namespace Aufbauwerk.Surfstation.Server
{
    class RadiusServer : IDisposable
    {
        static RadiusServer server;

        internal static void Start(object sender, StartEventArgs e)
        {
            // start the radius server
            server = new RadiusServer();
            server.Open();
        }

        internal static void Stop(object sender, EventArgs e)
        {
            // stop the radius server
            if (server != null)
                server.Close();
        }

        class Request
        {
            public IPEndPoint Client;
            public byte[][] ProxyStates;
            public byte Identifier;
            public byte[] Authenticator;
            public string UserName;
            public string Password;
            public string Address;
        }

        const int IOC_IN = -2147483648;
        const int IOC_VENDOR = 0x18000000;
        const int SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

        readonly byte[] sharedSecred;
        readonly Socket socket;
        readonly Thread thread;
        bool disposed;

        public RadiusServer()
        {
            // create a new server object
            this.sharedSecred = Encoding.UTF8.GetBytes(Program.Settings.RadiusSecret);
            this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.IOControl(SIO_UDP_CONNRESET, BitConverter.GetBytes(false), null);
            this.thread = new Thread(Listener);
            thread.IsBackground = true;
        }

        ~RadiusServer()
        {
            // dispose the object
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                // explicitly shutdown the server if not called from finalizer
                if (disposing)
                {
                    thread.Abort(); // won't have any effect yet, but prevents any SocketException from being thrown
                    socket.Close(); // actually interrupts ReceiveFrom and aborts the thread
                    thread.Join();  // wait for completion
                }
                disposed = true;
            }
        }

        void Listener()
        {
            // create the buffer and start listening
            var buffer = new byte[0x10000];
            while (true)
            {
                // receive the next message
                var endpoint = (EndPoint)new IPEndPoint(IPAddress.Any, 0);
                var length = socket.ReceiveFrom(buffer, ref endpoint);

                // if nothing is received, continue listening
                if (length == 0)
                    continue;

                // parse the packet and retrieve all necessary attributes
                var request = new Request();
                request.Client = (IPEndPoint)endpoint;
                try
                {
                    var packet = new RadiusPacket(buffer, length);
                    if (packet.Code != PacketCode.AccessRequest)
                        continue;
                    request.Identifier = packet.Identifier;
                    request.Authenticator = packet.Authenticator;
                    if (packet.Attribute(RadiusAttribute.CHAPPassword).Count > 0)
                        throw new FormatException("CHAP-Password is not supported");
                    var userNames = packet.Attribute(RadiusAttribute.UserName);
                    if (userNames.Count != 1)
                        throw new FormatException("User-Name is not present");
                    request.UserName = userNames[0];
                    if (packet.Attribute(RadiusAttribute.UserPassword).Count != 1)
                        throw new FormatException("User-Password is not present");
                    request.Password = packet.GetUserPassword(sharedSecred);
                    var callerIds = packet.Attribute(RadiusAttribute.CallingStationId);
                    request.Address = callerIds.Count > 0 ? callerIds[0] : null;
                    request.ProxyStates = packet.Attribute(RadiusAttribute.ProxyState).ToArray();
                }
#if DEBUG
                catch (FormatException e)
                {
                    ServiceApplication.LogEvent(EventLogEntryType.Information, e.Message);
                    continue;
                }
#else
                catch (FormatException) { continue; }
#endif

                // enqueue the request
                ThreadPool.QueueUserWorkItem(HandleRequest, request);
            }
        }

        int LogonAndCreateSession(string userName, string password, string address)
        {
            // open the database connection
            using (var connection = new OleDbConnection(Program.Settings.Database))
            {
                connection.Open();

                // verify the user and retrieve the timeout
                int id;
                object state;
                int timeout;
                using (var command = new OleDbCommand(Program.Settings.CommandInitialLogin, connection))
                {
                    command.Parameters.AddWithValue("@UserName", userName);
                    command.Parameters.AddWithValue("@Password", password);
                    using (var reader = command.ExecuteReader())
                    {
                        if (!reader.Read())
                            return -1;
                        id = (int)reader["ID"];
                        state = reader["State"];
                        timeout = (int)reader["Timeout"];
                        if (reader.Read())
                            return -1;
                    }
                }

                // create the session
                using (var command = new OleDbCommand(Program.Settings.CommandCreateSession, connection))
                {
                    command.Parameters.AddWithValue("@ID", id);
                    command.Parameters.AddWithValue("@State", state);
                    command.Parameters.AddWithValue("@Duration", timeout);
                    command.Parameters.AddWithValue("@Client", string.IsNullOrEmpty(address) ? DBNull.Value : (object)address);
                    if (command.ExecuteNonQuery() != 1)
                        return -1;
                }

                // return the timeout
                return timeout;
            }
        }

        void HandleRequest(object state)
        {
            // try to logon the user and create the response
            var request = (Request)state;
            int timeout;
            try { timeout = LogonAndCreateSession(request.UserName, request.Password, request.Address); }
            catch (OleDbException e)
            {
                ServiceApplication.LogEvent(EventLogEntryType.Error, e.Message);
                return;
            }
            var response = new RadiusPacket(timeout < 0 ? PacketCode.AccessReject : PacketCode.AccessAccept);
            response.Identifier = request.Identifier;
            if (timeout > 0)
                response.Attribute(RadiusAttribute.SessionTimeout).Add(timeout);
            response.Attribute(RadiusAttribute.ProxyState).AddRange(request.ProxyStates);
            response.SignResponse(request.Authenticator, sharedSecred);
            try { socket.SendTo(response.GetBuffer(), 0, response.Length, SocketFlags.None, request.Client); }
            catch (ObjectDisposedException) { }
            catch (SocketException e) { ServiceApplication.LogEvent(EventLogEntryType.Error, e.Message); }
        }

        public void Open()
        {
            // open the client and start the first receive operation
            if (disposed) throw new ObjectDisposedException(ToString());
            socket.Bind(new IPEndPoint(IPAddress.Parse(Program.Settings.RadiusAddress), Program.Settings.RadiusPort));
            thread.Start();
        }

        public void Close()
        {
            // just call dispose
            Dispose();
        }

        public void Dispose()
        {
            // dispose the server object
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
