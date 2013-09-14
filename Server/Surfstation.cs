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
using System.Data.OleDb;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.ServiceModel;
using System.Threading;
using Aufbauwerk.ServiceProcess;

namespace Aufbauwerk.Surfstation.Server
{
    static class ExceptionExtension
    {
        public static FaultException<T> AsFault<T>(this T e) where T : Exception
        {
            // convert an exception into a fault
            return new FaultException<T>(null, e.Message);
        }
    }

    class LogErrorBehaviorAttribute : Attribute, System.ServiceModel.Description.IServiceBehavior, System.ServiceModel.Dispatcher.IErrorHandler
    {
        void System.ServiceModel.Dispatcher.IErrorHandler.ProvideFault(Exception error, System.ServiceModel.Channels.MessageVersion version, ref System.ServiceModel.Channels.Message fault) { }
        void System.ServiceModel.Description.IServiceBehavior.AddBindingParameters(System.ServiceModel.Description.ServiceDescription serviceDescription, ServiceHostBase serviceHostBase, System.Collections.ObjectModel.Collection<System.ServiceModel.Description.ServiceEndpoint> endpoints, System.ServiceModel.Channels.BindingParameterCollection bindingParameters) { }
        void System.ServiceModel.Description.IServiceBehavior.Validate(System.ServiceModel.Description.ServiceDescription serviceDescription, ServiceHostBase serviceHostBase) { }

        bool System.ServiceModel.Dispatcher.IErrorHandler.HandleError(Exception error)
        {
            // ignore expected fault exceptions and log all other types
            if (!(error is FaultException))
                ServiceApplication.LogEvent(EventLogEntryType.Error, error.Message);
            return false;
        }

        void System.ServiceModel.Description.IServiceBehavior.ApplyDispatchBehavior(System.ServiceModel.Description.ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {
            // add the error handler to the list
            foreach (System.ServiceModel.Dispatcher.ChannelDispatcher channelDispatcher in serviceHostBase.ChannelDispatchers)
                channelDispatcher.ErrorHandlers.Add(this);
        }
    }

    [ServiceBehavior(InstanceContextMode = InstanceContextMode.PerSession)]
    [LogErrorBehavior]
    class Session : ISession, IDisposable
    {
        static ServiceHost host;
        static Timer timer;

        internal static void Start(object sender, StartEventArgs e)
        {
            // start the host and the screenshot-cleanup timer
            host = new ServiceHost(typeof(Session));
            host.Open();
            timer = new Timer(CleanupScreenshots, null, TimeSpan.Zero, Program.Settings.ScreenshotCleanupInterval);
        }

        internal static void Stop(object sender, EventArgs e)
        {
            // stop the timer and close the host
            if (timer != null)
                timer.Dispose();
            if (host != null)
                host.Close();
        }

        static void CleanupScreenshots(object state)
        {
            // clean up all out-of-date screenshots
            try
            {
                using (var connection = new OleDbConnection(Program.Settings.Database))
                {
                    connection.Open();
                    using (var command = new OleDbCommand(Program.Settings.CommandCleanupScreenshots, connection))
                    {
                        command.Parameters.AddWithValue("@Interval", Program.Settings.ScreenshotCleanupInterval.TotalSeconds);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (OleDbException e) { ServiceApplication.LogEvent(EventLogEntryType.Warning, e.Message); }
        }

        static Image LoadImageFromStream(Stream stream)
        {
            // load the image and throw all non-critical exceptions as faults
            try { return Image.FromStream(stream); }
            catch (StackOverflowException) { throw; }
            catch (OutOfMemoryException) { throw; }
            catch (ThreadAbortException) { throw; }
            catch (Exception e) { throw new FaultException(e.Message); }
        }

        bool disposed = false;
        bool ready = false;
        int databaseErrors = 0;
        DateTime sessionStart;
        OleDbConnection connection;
        int id;
        int session;
        object state;

        ~Session()
        {
            Dispose(false);
        }

        bool UpdateSession(byte[] image)
        {
            // update the session duration
            using (var command = new OleDbCommand(Program.Settings.CommandUpdateDuration, connection))
            {
                command.Parameters.AddWithValue("@Duration", (int)((DateTime.Now - sessionStart).TotalMinutes));
                command.Parameters.AddWithValue("@Session", session);
                if (command.ExecuteNonQuery() != 1)
                    return false;
            }

            // update the screenshot
            using (var command = new OleDbCommand(Program.Settings.CommandUpdateScreenshot, connection))
            {
                command.Parameters.AddWithValue("@Screenshot", (object)image ?? DBNull.Value);
                command.Parameters.AddWithValue("@Session", session);
                try { command.ExecuteNonQuery(); }
                catch (OleDbException e) { ServiceApplication.LogEvent(EventLogEntryType.Warning, e.Message); }
            }

            // return success
            return true;
        }

        protected virtual void Dispose(bool disposing)
        {
            // disconnect the connection if the object is explicitly disposed
            if (!disposed)
            {
                if (disposing && connection != null)
                    connection.Dispose();
                disposed = true;
            }
        }

        public bool Login(string userName, string password, string machineName)
        {
            // check the arguments and the session's state
            if (string.IsNullOrEmpty(userName)) throw new ArgumentNullException("userName").AsFault();
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password").AsFault();
            if (string.IsNullOrEmpty(machineName)) throw new ArgumentNullException("machineName").AsFault();
            if (disposed) throw new ObjectDisposedException(ToString()).AsFault();
            if (ready) throw new InvalidOperationException().AsFault();

            // open a connection to the database
            var connection = new OleDbConnection(Program.Settings.Database);
            try
            {
                connection.Open();

                // check if the user is allowed to logon on
                using (var command = new OleDbCommand(Program.Settings.CommandInitialLogin, connection))
                {
                    command.Parameters.AddWithValue("@UserName", userName);
                    command.Parameters.AddWithValue("@Password", password);
                    using (var reader = command.ExecuteReader())
                    {
                        if (!reader.Read())
                            return false;
                        id = (int)reader["ID"];
                        state = reader["State"];
                        if (reader.Read())
                            return false;
                    }
                }

                // create a new database session
                using (var transaction = connection.BeginTransaction())
                {
                    using (var command = new OleDbCommand(Program.Settings.CommandCreateSession, connection, transaction))
                    {
                        command.Parameters.AddWithValue("@ID", id);
                        command.Parameters.AddWithValue("@State", state);
                        command.Parameters.AddWithValue("@Duration", 0);
                        command.Parameters.AddWithValue("@Client", machineName);
                        if (command.ExecuteNonQuery() != 1)
                            return false;
                    }
                    using (var command = new OleDbCommand("SELECT @@IDENTITY", connection, transaction))
                        session = (int)command.ExecuteScalar();
                    transaction.Commit();
                }

                // notify the start time and put the session into the ready state
                sessionStart = DateTime.Now;
                ready = true;
                return true;
            }
            finally
            {
                // if everything went fine then store the connection, otherwise dispose it
                if (ready)
                    this.connection = connection;
                else
                    connection.Dispose();
            }
        }

        public bool Continue(Stream image)
        {
            // check the input argument and the state of the session
            if (image == null) throw new ArgumentNullException("image").AsFault();
            if (disposed) throw new ObjectDisposedException(ToString()).AsFault();
            if (!ready) new InvalidOperationException().AsFault();

            try
            {
                // ensure that the user is still allowed to logon
                using (var command = new OleDbCommand(Program.Settings.CommandVerifyLogin, connection))
                {
                    command.Parameters.AddWithValue("@ID", id);
                    command.Parameters.AddWithValue("@State", state);
                    if (!Convert.ToBoolean(command.ExecuteScalar()))
                        return false;
                }

                // load, adjust and store the screenshot and update the duration
                using (var screenshot = LoadImageFromStream(image))
                using (var zoomed = screenshot.Zoom(Program.Settings.ScreenshotSize.Width, Program.Settings.ScreenshotSize.Height, Program.Settings.ScreenshotFormat))
                    return UpdateSession(zoomed.ToOleObject(progId: "Screenshot", dde: "Screenshot", modifiable: false));
            }
            catch (OleDbException e)
            {
                // keep the session going as long as allowed
                if (databaseErrors++ < Program.Settings.DatabaseIgnoreUpdateErrors)
                {
                    ServiceApplication.LogEvent(EventLogEntryType.Error, e.Message);
                    return true;
                }

                // otherwise rethrow the error
                throw;
            }
        }

        public void Logout()
        {
            // check the state of the session
            if (disposed) throw new ObjectDisposedException(ToString()).AsFault();
            if (!ready) throw new InvalidOperationException().AsFault();

            // change the ready state, set the final duration, remove the screenshot and close the session
            ready = false;
            UpdateSession(null);
            Dispose();
        }

        public void Dispose()
        {
            // dispose the session
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
