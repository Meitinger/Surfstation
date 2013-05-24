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
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceProcess;
using System.Threading;

namespace Aufbauwerk.ServiceProcess
{
    public enum ServiceCommandContext
    {
        None, Continue, CustomCommand, Pause, PowerEvent, SessionChange, Shutdown, Start, Stop,
    }

    public class ServiceCustomCommandEventArgs : EventArgs
    {
        public ServiceCustomCommandEventArgs(int command)
        {
            Command = command;
        }

        public int Command { get; private set; }
    }

    public class ServicePowerEventEventArgs : CancelEventArgs
    {
        public ServicePowerEventEventArgs(PowerBroadcastStatus powerStatus)
        {
            PowerStatus = powerStatus;
        }
        public PowerBroadcastStatus PowerStatus { get; private set; }
    }

    public class ServiceSessionChangeEventArgs : EventArgs
    {
        public ServiceSessionChangeEventArgs(SessionChangeDescription changeDescription)
        {
            ChangeDescription = changeDescription;
        }

        public SessionChangeDescription ChangeDescription { get; private set; }
    }

    public class ServiceStartEventArgs : EventArgs
    {
        public ServiceStartEventArgs(string[] arguments)
        {
            Arguments = arguments;
        }

        public string[] Arguments { get; private set; }
    }

    public class ServiceExceptionEventArgs : CancelEventArgs
    {
        public ServiceExceptionEventArgs(ServiceCommandContext context, Exception exception)
        {
            if (exception == null)
                throw new ArgumentNullException("exception");
            Context = context;
            Exception = exception;
        }
        public ServiceCommandContext Context { get; private set; }
        public Exception Exception { get; private set; }
    }

    public class ServiceErrorHandlerBehaviorAttribute : Attribute, IServiceBehavior, IErrorHandler
    {
        public bool HandleFaultExceptions { get; set; }

        bool IErrorHandler.HandleError(Exception error) { return true; }

        void IErrorHandler.ProvideFault(Exception error, MessageVersion version, ref Message fault)
        {
            if (!(error is FaultException) || HandleFaultExceptions)
                ServiceApplication.OnException(error);
        }

        void IServiceBehavior.AddBindingParameters(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase, Collection<ServiceEndpoint> endpoints, BindingParameterCollection bindingParameters) { }

        void IServiceBehavior.ApplyDispatchBehavior(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase)
        {
            foreach (ChannelDispatcher channelDispatcher in serviceHostBase.ChannelDispatchers)
                channelDispatcher.ErrorHandlers.Add(this);
        }

        void IServiceBehavior.Validate(ServiceDescription serviceDescription, ServiceHostBase serviceHostBase) { }
    }

    public static class ServiceApplication
    {
        private class Service : ServiceBase
        {
            internal bool HandleError(ServiceCommandContext context, Exception exception)
            {
                ExitCode =
                    exception is ExternalException ? ((ExternalException)exception).ErrorCode :
                    exception.InnerException is ExternalException ? ((ExternalException)exception.InnerException).ErrorCode :
                    Marshal.GetHRForException(exception);
                var exceptionHandlers = Exception;
                if (exceptionHandlers == null)
                    return false;
                var args = new ServiceExceptionEventArgs(context, exception);
                exceptionHandlers.Invoke(this, args);
                if (args.Cancel)
                    instance.ExitCode = 0;
                return args.Cancel;
            }

            internal void RaiseEvent<T>(ServiceCommandContext context, EventHandler<T> handlers, T args) where T : EventArgs
            {
                if (handlers == null)
                    return;
                try { handlers.Invoke(this, args); }
                catch (Exception e)
                {
                    if (!HandleError(context, e))
                        throw;
                }
            }

            protected override void OnContinue()
            {
                RaiseEvent(ServiceCommandContext.Continue, ServiceApplication.Continue, EventArgs.Empty);
            }
            protected override void OnCustomCommand(int command)
            {
                RaiseEvent(ServiceCommandContext.CustomCommand, ServiceApplication.CustomCommand, new ServiceCustomCommandEventArgs(command));
            }
            protected override void OnPause()
            {
                RaiseEvent(ServiceCommandContext.Pause, ServiceApplication.Pause, EventArgs.Empty);
            }
            protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
            {
                var args = new ServicePowerEventEventArgs(powerStatus);
                RaiseEvent(ServiceCommandContext.PowerEvent, ServiceApplication.PowerEvent, args);
                return !args.Cancel;
            }
            protected override void OnSessionChange(SessionChangeDescription changeDescription)
            {
                RaiseEvent(ServiceCommandContext.SessionChange, ServiceApplication.SessionChange, new ServiceSessionChangeEventArgs(changeDescription));
            }
            protected override void OnShutdown()
            {
                RaiseEvent(ServiceCommandContext.Shutdown, ServiceApplication.Shutdown, EventArgs.Empty);
            }
            protected override void OnStart(string[] args)
            {
                try
                {
                    RaiseEvent(ServiceCommandContext.Start, ServiceApplication.Start, new ServiceStartEventArgs(args));
                }
                catch (Exception e)
                {
                    LogEvent(EventLogEntryType.Error, e.ToString());
                    Environment.Exit(instance.ExitCode);
                    throw;
                }
            }
            protected override void OnStop()
            {
                RaiseEvent(ServiceCommandContext.Stop, ServiceApplication.Stop, EventArgs.Empty);
            }
        }

        private static readonly Service instance = new Service();

        public static bool OnException(Exception exception)
        {
            if (instance.HandleError(ServiceCommandContext.None, exception))
                return true;
            LogEvent(EventLogEntryType.Error, exception.ToString());
            Environment.Exit(instance.ExitCode);
            return false;
        }

        public static void LogEvent(EventLogEntryType type, string message)
        {
            try
            {
#if DEBUG
                Console.Error.WriteLine("{0}: {1}", type, message);
#else
                instance.EventLog.WriteEntry(message, type);
#endif
            }
            catch (StackOverflowException) { throw; }
            catch (OutOfMemoryException) { throw; }
            catch (ThreadAbortException) { throw; }
            catch { }
        }

        public static void LogEvent(EventLogEntryType type, string format, params object[] args)
        {
            LogEvent(type, string.Format(format, args));
        }

        public static void Run()
        {
            instance.AutoLog = true;
            instance.CanHandlePowerEvent = PowerEvent != null;
            instance.CanHandleSessionChangeEvent = SessionChange != null;
            instance.CanPauseAndContinue = Pause != null && Continue != null;
            instance.CanShutdown = Shutdown != null;
            instance.CanStop = Stop != null;
            instance.ServiceName = Assembly.GetEntryAssembly().GetName().Name;
#if DEBUG
            instance.RaiseEvent(ServiceCommandContext.Start, ServiceApplication.Start, new ServiceStartEventArgs(Environment.GetCommandLineArgs()));
            Console.WriteLine("Press ENTER to stop...");
            Console.ReadLine();
            instance.RaiseEvent(ServiceCommandContext.Stop, ServiceApplication.Stop, EventArgs.Empty);
            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
#else
            ServiceBase.Run(instance);
#endif
        }

        public static void Exit(int exitCode = 0)
        {
            instance.ExitCode = exitCode;
            instance.Stop();
        }

        public static event EventHandler<EventArgs> Continue;
        public static event EventHandler<ServiceCustomCommandEventArgs> CustomCommand;
        public static event EventHandler<EventArgs> Pause;
        public static event EventHandler<ServicePowerEventEventArgs> PowerEvent;
        public static event EventHandler<ServiceSessionChangeEventArgs> SessionChange;
        public static event EventHandler<EventArgs> Shutdown;
        public static event EventHandler<ServiceStartEventArgs> Start;
        public static event EventHandler<EventArgs> Stop;
        public static event EventHandler<ServiceExceptionEventArgs> Exception;
    }
}
