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
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Aufbauwerk.Win32.SafeHandles;
using Microsoft.Win32.SafeHandles;

namespace Aufbauwerk.Win32.SafeHandles
{
    /// <summary>
    /// Represents a wrapper class for a process handle. 
    /// </summary>
    public sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("Kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool CloseHandle([In] IntPtr hObject);

        internal SafeProcessHandle(Process process)
            : base(false)
        {
            SetHandle(process.Handle);
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }
}

namespace Aufbauwerk.Security.AccessControl
{
    /// <summary>
    /// Static class containing extension methods for a <see cref="Process"/> object.
    /// </summary>
    public static class ProcessSecurityExtension
    {
        /// <summary>
        /// Gets a <see cref="ProcessSecurity"/> object that encapsulates the access control list (ACL) entries for the process described by the current <see cref="Process"/> object.
        /// </summary>
        /// <param name="process">The current process.</param>
        /// <returns>A <see cref="ProcessSecurity"/> object that encapsulates the access control rules for the current process.</returns>
        public static ProcessSecurity GetAccessControl(this Process process)
        {
            return new ProcessSecurity(new SafeProcessHandle(process), AccessControlSections.Group | AccessControlSections.Owner | AccessControlSections.Access);
        }

        /// <summary>
        /// Gets a <see cref="ProcessSecurity"/> object that encapsulates the access control list (ACL) entries for the process described by the current <see cref="Process"/> object.
        /// </summary>
        /// <param name="process">The current process.</param>
        /// <param name="includeSections">One of the <see cref="AccessControlSections"/> values that specifies which group of access control entries to retrieve.</param>
        /// <returns>A <see cref="ProcessSecurity"/> object that encapsulates the access control rules for the current process.</returns>
        public static ProcessSecurity GetAccessControl(this Process process, AccessControlSections includeSections)
        {
            return new ProcessSecurity(new SafeProcessHandle(process), includeSections);
        }

        /// <summary>
        /// Applies access control list (ACL) entries described by a <see cref="ProcessSecurity"/> object to the process described by the current <see cref="Process"/> object.
        /// </summary>
        /// <param name="process">The current process.</param>
        /// <param name="processSecurity">A <see cref="ProcessSecurity"/> object that describes an access control list (ACL) entry to apply to the current process.</param>
        public static void SetAccessControl(this Process process, ProcessSecurity processSecurity)
        {
            processSecurity.Persist(new SafeProcessHandle(process));
        }
    }

    /// <summary>
    /// Defines the access rights to use when creating access and audit rules.
    /// </summary>
    [Flags]
    public enum ProcessRights : uint
    {
        Delete = 0x10000,
        ReadPermissions = 0x20000,
        ChangePermissions = 0x40000,
        TakeOwnership = 0x80000,
        Synchronize = 0x100000,
        Terminate = 0x0001,
        CreateThread = 0x0002,
        VirtualMemoryOperation = 0x0008,
        VirtualMemoryRead = 0x0010,
        VirtualMemoryWrite = 0x0020,
        DuplicateHandle = 0x0040,
        CreateProcess = 0x0080,
        SetQuota = 0x0100,
        SetInformation = 0x0200,
        QueryInformation = 0x0400,
        SuspendResume = 0x0800,
    }

    /// <summary>
    /// Represents an abstraction of an access control entry (ACE) that defines an access rule for a process. This class cannot be inherited.
    /// </summary>
    public sealed class ProcessAccessRule : AccessRule
    {
        public ProcessAccessRule(IdentityReference identity, ProcessRights processRights, AccessControlType type)
            : this(identity, (int)processRights, false, InheritanceFlags.None, PropagationFlags.None, type) { }

        public ProcessAccessRule(string identity, ProcessRights processRights, AccessControlType type)
            : this(new NTAccount(identity), (int)processRights, false, InheritanceFlags.None, PropagationFlags.None, type) { }

        internal ProcessAccessRule(IdentityReference identity, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
            : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, type) { }

        public ProcessRights ProcessRights { get { return (ProcessRights)base.AccessMask; } }
    }

    /// <summary>
    /// Represents an abstraction of an access control entry (ACE) that defines an audit rule for a process. This class cannot be inherited.
    /// </summary>
    public sealed class ProcessAuditRule : AuditRule
    {
        public ProcessAuditRule(IdentityReference identity, ProcessRights processRights, AuditFlags flags)
            : this(identity, (int)processRights, false, InheritanceFlags.None, PropagationFlags.None, flags) { }

        internal ProcessAuditRule(IdentityReference identity, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
            : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags, flags) { }

        public ProcessRights ProcessRights { get { return (ProcessRights)base.AccessMask; } }
    }

    /// <summary>
    /// Represents the access control and audit security for a process.
    /// </summary>
    public sealed class ProcessSecurity : NativeObjectSecurity
    {
        public ProcessSecurity() : base(true, ResourceType.KernelObject) { }

        internal ProcessSecurity(SafeProcessHandle processHandle, AccessControlSections includeSections)
            : base(true, ResourceType.KernelObject, processHandle, includeSections) { }

        internal void Persist(SafeProcessHandle handle)
        {
            base.WriteLock();
            try
            {
                var sections = AccessControlSections.None;
                if (base.AccessRulesModified)
                    sections |= AccessControlSections.Access;
                if (base.AuditRulesModified)
                    sections |= AccessControlSections.Audit;
                if (base.OwnerModified)
                    sections |= AccessControlSections.Owner;
                if (base.GroupModified)
                    sections |= AccessControlSections.Group;
                if (sections != AccessControlSections.None)
                    base.Persist(handle, sections);
            }
            finally
            {
                base.WriteUnlock();
            }
        }

        public override Type AccessRightType
        {
            get { return typeof(ProcessRights); }
        }

        public override AccessRule AccessRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AccessControlType type)
        {
            return new ProcessAccessRule(identityReference, accessMask, isInherited, inheritanceFlags, propagationFlags, type);
        }

        public void AddAccessRule(ProcessAccessRule rule)
        {
            base.AddAccessRule(rule);
        }

        public bool RemoveAccessRule(ProcessAccessRule rule)
        {
            return base.RemoveAccessRule(rule);
        }

        public void RemoveAccessRuleAll(ProcessAccessRule rule)
        {
            base.RemoveAccessRuleAll(rule);
        }

        public void RemoveAccessRuleSpecific(ProcessAccessRule rule)
        {
            base.RemoveAccessRuleSpecific(rule);
        }

        public void SetAccessRule(ProcessAccessRule rule)
        {
            base.SetAccessRule(rule);
        }

        public void ResetAccessRule(ProcessAccessRule rule)
        {
            base.ResetAccessRule(rule);
        }

        public override Type AccessRuleType
        {
            get { return typeof(ProcessAccessRule); }
        }

        public override AuditRule AuditRuleFactory(IdentityReference identityReference, int accessMask, bool isInherited, InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags, AuditFlags flags)
        {
            return new ProcessAuditRule(identityReference, accessMask, isInherited, inheritanceFlags, propagationFlags, flags);
        }

        public void AddAuditRule(ProcessAuditRule rule)
        {
            base.AddAuditRule(rule);
        }

        public bool RemoveAuditRule(ProcessAuditRule rule)
        {
            return base.RemoveAuditRule(rule);
        }

        public void RemoveAuditRuleAll(ProcessAuditRule rule)
        {
            base.RemoveAuditRuleAll(rule);
        }

        public void RemoveAuditRuleSpecific(ProcessAuditRule rule)
        {
            base.RemoveAuditRuleSpecific(rule);
        }

        public void SetAuditRule(ProcessAuditRule rule)
        {
            base.SetAuditRule(rule);
        }

        public override Type AuditRuleType
        {
            get { return typeof(ProcessAuditRule); }
        }
    }
}
