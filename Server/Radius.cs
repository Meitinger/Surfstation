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
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Aufbauwerk.Net.Radius
{
    #region Enumerations

    public enum PacketCode : byte
    {
        AccessRequest = 1,
        AccessAccept = 2,
        AccessReject = 3,
        AccountingRequest = 4,
        AccountingResponse = 5,
        AccessChallenge = 11,
    }
    public enum ServiceType
    {
        Login = 1,
        Framed = 2,
        CallbackLogin = 3,
        CallbackFramed = 4,
        Outbound = 5,
        Administrative = 6,
        NASPrompt = 7,
        AuthenticateOnly = 8,
        CallbackNASPrompt = 9,
        CallCheck = 10,
        CallbackAdministrative = 11,
    }
    public enum FramedProtocol
    {
        PPP = 1,
        SLIP = 2,
        ARAP = 3,
        Gandalf_SLMLP = 4,
        Xylogics_IPX_SLIP = 5,
        X75_Synchronous = 6,
    }
    public enum FramedRouting
    {
        None = 0,
        Send = 1,
        Listen = 2,
        SendAndListen = 3,
    }
    public enum FramedCompression
    {
        None = 0,
        TCPIP = 1,
        IPX = 2,
        LZS = 3,
    }
    public enum LoginService
    {
        Telnet = 0,
        Rlogin = 1,
        TCP_Clear = 2,
        PortMaster = 3,
        LAT = 4,
        X25_PAD = 5,
        X25_T3POS = 6,
        TCP_Clear_Quiet = 8,
    }
    public enum TerminationAction
    {
        Default = 0,
        RADIUSRequest = 1,
    }
    public enum AcctStatusType
    {
        Start = 1,
        Stop = 2,
        InterimUpdate = 3,
        Alive = 3,
        AccountingOn = 7,
        AccountingOff = 8,
        Failed = 15,
    }
    public enum AcctAuthentic
    {
        RADIUS = 1,
        Local = 2,
        Remote = 3,
    }
    public enum AcctTerminateCause
    {
        UserRequest = 1,
        LostCarrier = 2,
        LostService = 3,
        IdleTimeout = 4,
        SessionTimeout = 5,
        AdminReset = 6,
        AdminReboot = 7,
        PortError = 8,
        NASError = 9,
        NASRequest = 10,
        NASReboot = 11,
        PortUnneeded = 12,
        PortPreempted = 13,
        PortSuspended = 14,
        ServiceUnavailable = 15,
        Callback = 16,
        UserError = 17,
        HostRequest = 18,
    }
    public enum NASPortType
    {
        Async = 0,
        Sync = 1,
        ISDN_Sync = 2,
        ISDN_Async_V120 = 3,
        ISDN_Async_V110 = 4,
        Virtual = 5,
        PIAFS = 6,
        HDLC_Clear_Channel = 7,
        X25 = 8,
        X75 = 9,
        G3_Fax = 10,
        SDSL = 11,
        ADSL_CAP = 12,
        ADSL_DMT = 13,
        IDSL = 14,
        Ethernet = 15,
        xDSL = 16,
        Cable = 17,
        Wireless_Other = 18,
        Wireless_IEEE_802_11 = 19,
    }
    public enum Prompt
    {
        NoEcho = 0,
        Echo = 1,
    }

    #endregion

    /// <summary>
    /// A RADIUS packet implementation.
    /// </summary>
    public class RadiusPacket
    {
        private static readonly RandomNumberGenerator RNG = RandomNumberGenerator.Create();
        private static readonly byte[] EmptyAuthenticator = new byte[16];
        private readonly Dictionary<byte, List<int>> attributeOffsets = new Dictionary<byte, List<int>>();
        private readonly byte[] buffer;

        /// <summary>
        /// Creates an empty RADIUS packet.
        /// </summary>
        /// <param name="code">The packet type.</param>
        public RadiusPacket(PacketCode code)
        {
            this.buffer = new byte[4096];
            IsReadOnly = false;
            Code = code;
            Length = 20;
        }

        /// <summary>
        /// Parses a given binary representation of a RADIUS packet.
        /// </summary>
        /// <param name="buffer">The byte array to parse.</param>
        /// <param name="length">The amount of bytes to parse.</param>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is negative or greater then the length of <paramref name="buffer"/>.</exception>
        /// <exception cref="FormatException"><paramref name="buffer"/> contains invalid data.</exception>
        public RadiusPacket(byte[] buffer, int length)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (length < 0 || length > buffer.Length) throw new ArgumentOutOfRangeException("length");
            this.buffer = buffer;
            IsReadOnly = false;
            if (length < 20 || Length < 20)
                throw new FormatException("Message is too short");
            if (Length > length)
                throw new FormatException("Message is incomplete");
            if (length > 4096)
                throw new FormatException("Message is too long");
            var offset = 20;
            while (offset < Length)
            {
                if (offset + 2 > Length)
                    throw new FormatException("Attribute is incomplete");
                var newOffset = offset + buffer[offset + 1];
                if (newOffset > Length)
                    throw new FormatException(string.Format("Attribute {0} overruns buffer", buffer[offset]));
                List<int> offsets;
                if (!attributeOffsets.TryGetValue(buffer[offset], out offsets))
                    attributeOffsets.Add(buffer[offset], offsets = new List<int>());
                offsets.Add(offset);
                offset = newOffset;
            }
            IsReadOnly = true;
        }

        private void CorrectOffsets(int offset, int length)
        {
            // adjust the packet size, move the actual data and update all affected offsets
            Length += length;
            Array.Copy(buffer, offset, buffer, offset + length, Length - (offset + length));
            foreach (var offsets in attributeOffsets.Values)
                for (var i = offsets.Count - 1; i >= 0; i--)
                    if (offsets[i] >= offset)
                        offsets[i] += length;
        }

        private List<int> OffsetsFromParser<T>(RadiusAttributeParser<T> parser)
        {
            // return the offsets for a given attribute type
            List<int> offsets;
            if (!attributeOffsets.TryGetValue(parser.Type, out offsets))
                attributeOffsets.Add(parser.Type, offsets = new List<int>());
            return offsets;
        }

        private void Sign(byte[] authenticatorBuffer, int offset, byte[] sharedSecret)
        {
            // set the given authenticator, create the md5 of the packet and store it as the new authenticator
            Array.Copy(authenticatorBuffer, offset, buffer, 4, 16);
            using (var md5 = MD5.Create())
            {
                md5.TransformBlock(buffer, 0, Length, buffer, 0);
                md5.TransformFinalBlock(sharedSecret, 0, sharedSecret.Length);
                Array.Copy(md5.Hash, 0, buffer, 4, 16);
            }
        }

        private bool Verify(byte[] authenticatorBuffer, int offset, byte[] sharedSecret)
        {
            // create the md5 of code+identifier+original_authenticator+attributes+shared_secret and compare it with the authenticator
            using (var md5 = MD5.Create())
            {
                md5.TransformBlock(buffer, 0, 4, buffer, 0);
                md5.TransformBlock(authenticatorBuffer, offset, 16, authenticatorBuffer, 0);
                md5.TransformBlock(buffer, 20, Length - 20, buffer, 20);
                md5.TransformFinalBlock(sharedSecret, 0, sharedSecret.Length);
                var hash = md5.Hash;
                for (var i = 0; i < 16; i++)
                    if (hash[i] != buffer[i + 4])
                        return false;
                return true;
            }
        }

        internal void InsertAttribute<T>(RadiusAttributeParser<T> parser, int index, T item)
        {
            // check for not read-only
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");

            // determine offset
            var offsets = OffsetsFromParser(parser);
            var offset = index == offsets.Count ? Length : offsets[index];

            // parse value into a byte array
            var attribute = parser.Write(item);
            var length = attribute.Length + 2;
            if (length > byte.MaxValue)
                throw new ArgumentOutOfRangeException("item");

            // prepare buffer
            CorrectOffsets(offset, length);

            // write attribute
            buffer[offset] = parser.Type;
            buffer[offset + 1] = (byte)length;
            Array.Copy(attribute, 0, buffer, offset + 2, length - 2);

            // store offset
            offsets.Insert(index, offset);
        }

        internal void RemoveAttribute<T>(RadiusAttributeParser<T> parser, int index)
        {
            // check for not read-only
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");

            // determine offset and length
            var offsets = OffsetsFromParser(parser);
            var offset = offsets[index];
            var length = buffer[offset + 1];

            // remove attribute from buffer
            CorrectOffsets(offset + length, -length);

            // delete offset
            offsets.RemoveAt(index);
        }

        internal T GetAttribute<T>(RadiusAttributeParser<T> parser, int index)
        {
            // read attribute
            var offset = OffsetsFromParser(parser)[index];
            return parser.Read(buffer, offset + 2, buffer[offset + 1] - 2);
        }

        internal void SetAttribute<T>(RadiusAttributeParser<T> parser, int index, T value)
        {
            // check for not read-only
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");

            // determine offset and old length
            var offset = OffsetsFromParser(parser)[index];
            var oldLength = buffer[offset + 1];

            // parse value into byte array
            var attribute = parser.Write(value);
            var newLength = attribute.Length + 2;
            if (newLength > byte.MaxValue)
                throw new ArgumentOutOfRangeException("value");

            // prepare buffer if necessary
            if (oldLength != newLength)
                CorrectOffsets(offset + oldLength, newLength - oldLength);

            // write attribute
            buffer[offset] = parser.Type;
            buffer[offset + 1] = (byte)newLength;
            Array.Copy(attribute, 0, buffer, offset + 2, attribute.Length);
        }

        internal int CountAttribute<T>(RadiusAttributeParser<T> parser)
        {
            // return the number of attribute of the given type
            var offsets = OffsetsFromParser(parser);
            return offsets.Count;
        }

        /// <summary>
        /// Accesses and modifies attributes within the packet.
        /// </summary>
        /// <typeparam name="T">The value type of <paramref name="parser"/>.</typeparam>
        /// <param name="parser">The attribute parser, either one of <see cref="RadiusAttribute"/> members or a custom one.</param>
        /// <returns>A modifiable list of all attribute values with the same type as <paramref name="parser"/>.</returns>
        public RadiusAttributeList<T> Attribute<T>(RadiusAttributeParser<T> parser) { return new RadiusAttributeList<T>(this, parser); }

        /// <summary>
        /// Indicates whether the packet is read-only or not.
        /// </summary>
        public bool IsReadOnly { get; private set; }

        /// <summary>
        /// A packet code specifying the kind of request or response.
        /// </summary>
        public PacketCode Code
        {
            get { return (PacketCode)buffer[0]; }
            private set { buffer[0] = (byte)value; }
        }

        /// <summary>
        /// A single byte identifying the packet.
        /// </summary>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public byte Identifier
        {
            get { return buffer[1]; }
            set
            {
                if (IsReadOnly)
                    throw new NotSupportedException("RadiusPacket is read-only");
                buffer[1] = value;
            }
        }

        /// <summary>
        /// The current size in bytes of this packet.
        /// </summary>
        public int Length
        {
            get { return buffer[2] << 8 | buffer[3]; }
            private set
            {
                if (value > buffer.Length || value < 20)
                    throw new ArgumentOutOfRangeException("Length");
                buffer[2] = (byte)(value >> 8);
                buffer[3] = (byte)value;
            }
        }

        /// <summary>
        /// The packet's request or response authenticator.
        /// </summary>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public byte[] Authenticator
        {
            get
            {
                var authenticator = new byte[16];
                Array.Copy(buffer, 4, authenticator, 0, 16);
                return authenticator;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("Authenticator");
                if (value.Length != 16)
                    throw new ArgumentOutOfRangeException("Authenticator");
                if (IsReadOnly)
                    throw new NotSupportedException("RadiusPacket is read-only");
                Array.Copy(value, 0, buffer, 4, 16);
            }
        }

        /// <summary>
        /// Creates the default <see cref="Authenticator"/> for a request packet.
        /// </summary>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <remarks>
        /// This method does not apply to packets where <see cref="Code"/> equals <see cref="PacketCode.AccessRequest"/>.
        /// </remarks>
        /// <exception cref="ArgumentNullException"><paramref name="sharedSecret"/> is <c>null</c>.</exception>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public void SignRequest(byte[] sharedSecret)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");
            Sign(EmptyAuthenticator, 0, sharedSecret);
        }

        /// <summary>
        /// Creates the default <see cref="Authenticator"/> for a response packet to a given request.
        /// </summary>
        /// <param name="requestPacket">The RADIUS request packet to this response.</param>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <exception cref="ArgumentNullException"><paramref name="requestPacket"/> or <paramref name="sharedSecret"/> is <c>null</c>.</exception>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public void SignResponse(RadiusPacket requestPacket, byte[] sharedSecret)
        {
            if (requestPacket == null)
                throw new ArgumentNullException("requestPacket");
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");
            Sign(requestPacket.buffer, 4, sharedSecret);
        }

        /// <summary>
        /// Creates the default <see cref="Authenticator"/> for a response packet to a given request.
        /// </summary>
        /// <param name="requestPacketAuthenticator">The authenticator of the RADIUS request packet to this response.</param>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <exception cref="ArgumentNullException"><paramref name="requestPacketAuthenticator"/> or <paramref name="sharedSecret"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException"><paramref name="requestPacketAuthenticator"/> is invalid.</exception>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public void SignResponse(byte[] requestPacketAuthenticator, byte[] sharedSecret)
        {
            if (requestPacketAuthenticator == null)
                throw new ArgumentNullException("requestPacketAuthenticator");
            if (requestPacketAuthenticator.Length != 16)
                throw new ArgumentException("Authenticator is not valid", "requestPacketAuthenticator");
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");
            Sign(requestPacketAuthenticator, 0, sharedSecret);
        }

        /// <summary>
        /// Verifies that the packet's <see cref="Authenticator"/> is a valid request authenticator.
        /// </summary>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <remarks>
        /// This method does not apply to packets where <see cref="Code"/> equals <see cref="PacketCode.AccessRequest"/>.
        /// </remarks>
        /// <returns><c>true</c> if <see cref="Authenticator"/> is value, otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="sharedSecret"/> is <c>null</c>.</exception>
        public bool VerifyRequest(byte[] sharedSecret)
        {
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            return Verify(EmptyAuthenticator, 0, sharedSecret);
        }

        /// <summary>
        /// Verifies that the packet's <see cref="Authenticator"/> is a valid response authenticator.
        /// </summary>
        /// <param name="requestPacket">The RADIUS request packet to this response.</param>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <returns><c>true</c> if <see cref="Authenticator"/> is value, otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="requestPacket"/> or <paramref name="sharedSecret"/> is <c>null</c>.</exception>
        public bool VerifyResponse(RadiusPacket requestPacket, byte[] sharedSecret)
        {
            if (requestPacket == null)
                throw new ArgumentNullException("requestPacket");
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            return Verify(requestPacket.buffer, 4, sharedSecret);
        }

        /// <summary>
        /// Verifies that the packet's <see cref="Authenticator"/> is a valid response authenticator.
        /// </summary>
        /// <param name="requestPacketAuthenticator">The authenticator of the RADIUS request packet to this response.</param>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <returns><c>true</c> if <see cref="Authenticator"/> is value, otherwise <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="requestPacketAuthenticator"/> or <paramref name="sharedSecret"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException"><paramref name="requestPacketAuthenticator"/> is invalid.</exception>
        public bool VerifyResponse(byte[] requestPacketAuthenticator, byte[] sharedSecret)
        {
            if (requestPacketAuthenticator == null)
                throw new ArgumentNullException("requestPacketAuthenticator");
            if (requestPacketAuthenticator.Length != 16)
                throw new ArgumentException("Authenticator is not valid", "requestPacketAuthenticator");
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            return Verify(requestPacketAuthenticator, 0, sharedSecret);
        }

        /// <summary>
        /// Stores the given <paramref name="password"/> as <see cref="RadiusAttribute.UserPassword"/> within the packets attributes, removing any previously existing, and randomizes the <see cref="Authenticator"/>.
        /// </summary>
        /// <param name="password">The user password in plain-text.</param>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="password"/> is longer than 128 bytes.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="sharedSecret"/> is <c>null</c>.</exception>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public void SetUserPassword(string password, byte[] sharedSecret)
        {
            // check all necessary variables
            if (password == null)
                throw new ArgumentNullException("password");
            var passwordBuffer = Encoding.UTF8.GetBytes(password);
            if (passwordBuffer.Length > 128)
                throw new ArgumentOutOfRangeException("password");
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");

            // round the password buffer up to the next 16 bytes boundary
            var remainder = passwordBuffer.Length % 16;
            if (remainder > 0)
                Array.Resize(ref passwordBuffer, passwordBuffer.Length + (16 - remainder));

            // set a random authenticator
            var authenticator = new byte[16];
            lock (RNG)
                RNG.GetBytes(authenticator);
            Array.Copy(authenticator, 0, buffer, 4, 16);

            // encode the password
            using (var md5 = MD5.Create())
            {
                md5.TransformBlock(sharedSecret, 0, sharedSecret.Length, sharedSecret, 0);
                md5.TransformFinalBlock(buffer, 4, 16);
                for (var i = 0; i < passwordBuffer.Length; i += 16)
                {
                    var hash = md5.Hash;
                    md5.Initialize();
                    for (var j = 0; j < 16; j++)
                        passwordBuffer[j + i] ^= hash[j];
                    md5.TransformBlock(sharedSecret, 0, sharedSecret.Length, sharedSecret, 0);
                    md5.TransformFinalBlock(passwordBuffer, i, 16);
                }
            }

            // actually store the password
            var attribute = Attribute(RadiusAttribute.UserPassword);
            switch (attribute.Count)
            {
                case 0:
                    attribute.Add(passwordBuffer);
                    break;
                case 1:
                    attribute[0] = passwordBuffer;
                    break;
                default:
                    attribute.Clear();
                    goto case 0;
            }
        }

        /// <summary>
        /// Retrieves the password stored within the <see cref="RadiusAttribute.UserPassword"/> attribute.
        /// </summary>
        /// <param name="sharedSecret">The shared RADIUS secret.</param>
        /// <returns>The user password in plain-text.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="sharedSecret"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">None or more than one <see cref="RadiusAttribute.UserPassword"/> is present.</exception>
        /// <exception cref="FormatException"><see cref="RadiusAttribute.UserPassword"/> is invalid.</exception>
        public string GetUserPassword(byte[] sharedSecret)
        {
            // check the necessary variables
            if (sharedSecret == null)
                throw new ArgumentNullException("sharedSecret");
            var attribute = Attribute(RadiusAttribute.UserPassword);
            switch (attribute.Count)
            {
                case 0: throw new InvalidOperationException("User-Password is not set");
                case 1: break;
                default: throw new InvalidOperationException("User-Password is not unique");
            }
            var passwordBuffer = attribute[0];
            if (passwordBuffer.Length > 128 || passwordBuffer.Length % 16 > 0)
                throw new FormatException("User-Password is not valid");

            // decode the password
            using (var md5 = MD5.Create())
            {
                md5.TransformBlock(sharedSecret, 0, sharedSecret.Length, sharedSecret, 0);
                md5.TransformFinalBlock(buffer, 4, 16);
                for (var i = 0; i < passwordBuffer.Length; i += 16)
                {
                    var hash = md5.Hash;
                    md5.Initialize();
                    md5.TransformBlock(sharedSecret, 0, sharedSecret.Length, sharedSecret, 0);
                    md5.TransformFinalBlock(passwordBuffer, i, 16);
                    for (var j = 0; j < 16; j++)
                        passwordBuffer[j + i] ^= hash[j];
                }
            }
            return Encoding.UTF8.GetString(passwordBuffer).TrimEnd('\0');
        }

        /// <summary>
        /// Retrieves the internal buffer for transmission of the packet. This buffer is not truncated to the length of the packet.
        /// </summary>
        /// <returns>The underlying buffer of this RADIUS packet.</returns>
        /// <exception cref="NotSupportedException">The packet is read-only.</exception>
        public byte[] GetBuffer()
        {
            if (IsReadOnly)
                throw new NotSupportedException("RadiusPacket is read-only");
            return buffer;
        }
    }

    #region Attributes

    #region Parsers

    public sealed class RadiusIntegerAttributeParser : RadiusBaseIntegerAttributeParser<int>
    {
        public RadiusIntegerAttributeParser(byte type) : base(type) { }

        protected override int ReadInt(int rawValue)
        {
            return rawValue;
        }

        protected override int WriteInt(int value)
        {
            return value;
        }
    }
    public sealed class RadiusStringAttributeParser : RadiusAttributeParser<string>
    {
        public RadiusStringAttributeParser(byte type) : base(type) { }

        public override string Read(byte[] buffer, int offset, int length)
        {
            try { return Encoding.UTF8.GetString(buffer, offset, length); }
            catch (DecoderFallbackException e) { throw new FormatException(string.Format("Attribute {0} contains an invalid string", Type), e); }
        }

        public override byte[] Write(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }
    }
    public sealed class RadiusIPAddressAttributeParser : RadiusAttributeParser<IPAddress>
    {
        private readonly int length;

        public RadiusIPAddressAttributeParser(byte type, bool isV6 = false)
            : base(type)
        {
            length = isV6 ? 16 : 4;
        }

        public override IPAddress Read(byte[] buffer, int offset, int length)
        {
            if (this.length != length) throw new FormatException(string.Format("Attribute {0} contains an invalid IPv{1} address", Type, this.length % 10));
            var ip = new byte[length];
            Array.Copy(buffer, offset, ip, 0, length);
            return new IPAddress(ip);
        }

        public override byte[] Write(IPAddress value)
        {
            var buffer = value.GetAddressBytes();
            if (buffer.Length != length)
                throw new ArgumentOutOfRangeException("value");
            return buffer;
        }
    }
    public sealed class RadiusBinaryAttributeParser : RadiusAttributeParser<byte[]>
    {
        public RadiusBinaryAttributeParser(byte type) : base(type) { }

        public override byte[] Read(byte[] buffer, int offset, int length)
        {
            var result = new byte[length];
            Array.Copy(buffer, offset, result, 0, length);
            return result;
        }

        public override byte[] Write(byte[] value)
        {
            return value;
        }
    }
    public sealed class RadiusDateTimeAttributeParser : RadiusBaseIntegerAttributeParser<DateTime>
    {
        private readonly static DateTime Epoche = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public RadiusDateTimeAttributeParser(byte type) : base(type) { }

        protected override DateTime ReadInt(int rawValue)
        {
            return Epoche.AddSeconds(rawValue);
        }

        protected override int WriteInt(DateTime value)
        {
            return (int)(value.ToUniversalTime() - Epoche).TotalSeconds;
        }
    }
    public sealed class RadiusEnumAttributeParser<T> : RadiusBaseIntegerAttributeParser<T> where T : struct
    {
        public RadiusEnumAttributeParser(byte type) : base(type) { Debug.Assert(typeof(T).IsEnum); }

        protected override T ReadInt(int rawValue)
        {
            return (T)Enum.ToObject(typeof(T), rawValue);
        }

        protected override int WriteInt(T value)
        {
            return Convert.ToInt32(value);
        }
    }
    public abstract class RadiusBaseIntegerAttributeParser<T> : RadiusAttributeParser<T>
    {
        protected RadiusBaseIntegerAttributeParser(byte type) : base(type) { }

        protected abstract T ReadInt(int rawValue);

        protected abstract int WriteInt(T value);

        public sealed override T Read(byte[] buffer, int offset, int length)
        {
            if (length != 4) throw new FormatException(string.Format("Attribute {0} is invalid", Type));
            return ReadInt((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | (buffer[offset + 3] & 0xff));
        }

        public sealed override byte[] Write(T value)
        {
            var rawValue = WriteInt(value);
            var buffer = new byte[4];
            buffer[0] = (byte)(rawValue >> 24);
            buffer[1] = (byte)(rawValue >> 16);
            buffer[2] = (byte)(rawValue >> 8);
            buffer[3] = (byte)(rawValue);
            return buffer;
        }
    }
    public abstract class RadiusAttributeParser<T>
    {
        private readonly byte type;

        protected RadiusAttributeParser(byte type) { this.type = type; }

        public byte Type { get { return type; } }

        public abstract T Read(byte[] buffer, int offset, int length);

        public abstract byte[] Write(T value);
    }

    #endregion

    /// <summary>
    /// A list of attribute values.
    /// </summary>
    /// <typeparam name="T">The value type of underlying <see cref="RadiusAttributeParser{T}"/>.</typeparam>
    public class RadiusAttributeList<T> : IList<T>
    {
        private readonly RadiusPacket packet;
        private readonly RadiusAttributeParser<T> parser;

        internal RadiusAttributeList(RadiusPacket packet, RadiusAttributeParser<T> parser)
        {
            this.packet = packet;
            this.parser = parser;
        }

        public void Insert(int index, T item) { packet.InsertAttribute(parser, index, item); }

        public void RemoveAt(int index) { packet.RemoveAttribute(parser, index); }

        public T this[int index]
        {
            get { return packet.GetAttribute(parser, index); }
            set { packet.SetAttribute(parser, index, value); }
        }

        public int Count { get { return packet.CountAttribute(parser); } }

        public bool IsReadOnly { get { return packet.IsReadOnly; } }

        #region derived list functions

        public void AddRange(IEnumerable<T> collection)
        {
            this.InsertRange(Count, collection);
        }

        public void InsertRange(int index, IEnumerable<T> collection)
        {
            foreach (var item in collection)
                Insert(index++, item);
        }

        public T[] ToArray()
        {
            var buffer = new T[Count];
            for (var i = 0; i < buffer.Length; i++)
                buffer[i] = packet.GetAttribute(parser, i);
            return buffer;
        }

        public T Peek()
        {
            var position = Count - 1;
            if (position == -1)
                throw new InvalidOperationException();
            return this[position];
        }

        public void Push(T item)
        {
            Add(item);
        }

        public T Pop()
        {
            var position = Count - 1;
            if (position == -1)
                throw new InvalidOperationException();
            var result = this[position];
            RemoveAt(position);
            return result;
        }

        public int IndexOf(T item)
        {
            for (var i = 0; i < Count; i++)
                if (object.Equals(this[i], item))
                    return i;
            return -1;
        }

        public void Add(T item)
        {
            Insert(Count, item);
        }

        public void Clear()
        {
            for (var i = Count - 1; i >= 0; i--)
                RemoveAt(i);
        }

        public bool Contains(T item)
        {
            return IndexOf(item) != -1;
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            for (var i = 0; i < Count; i++)
                array[arrayIndex++] = this[i];
        }

        public bool Remove(T item)
        {
            var index = IndexOf(item);
            if (index == -1)
                return false;
            RemoveAt(index);
            return true;
        }

        public IEnumerator<T> GetEnumerator()
        {
            for (var i = 0; i < Count; i++)
                yield return this[i];
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        #endregion
    }

    /// <summary>
    /// A static class that defines common RADIUS attributes.
    /// </summary>
    public static class RadiusAttribute
    {
        public static readonly RadiusStringAttributeParser UserName = new RadiusStringAttributeParser(1);
        public static readonly RadiusBinaryAttributeParser UserPassword = new RadiusBinaryAttributeParser(2);
        public static readonly RadiusBinaryAttributeParser CHAPPassword = new RadiusBinaryAttributeParser(3);
        public static readonly RadiusIPAddressAttributeParser NASIPAddress = new RadiusIPAddressAttributeParser(4);
        public static readonly RadiusIntegerAttributeParser NASPort = new RadiusIntegerAttributeParser(5);
        public static readonly RadiusEnumAttributeParser<ServiceType> ServiceType = new RadiusEnumAttributeParser<ServiceType>(6);
        public static readonly RadiusEnumAttributeParser<FramedProtocol> FramedProtocol = new RadiusEnumAttributeParser<FramedProtocol>(7);
        public static readonly RadiusIPAddressAttributeParser FramedIPAddress = new RadiusIPAddressAttributeParser(8);
        public static readonly RadiusIPAddressAttributeParser FramedIPNetmask = new RadiusIPAddressAttributeParser(9);
        public static readonly RadiusEnumAttributeParser<FramedRouting> FramedRouting = new RadiusEnumAttributeParser<FramedRouting>(10);
        public static readonly RadiusStringAttributeParser FilterId = new RadiusStringAttributeParser(11);
        public static readonly RadiusIntegerAttributeParser FramedMTU = new RadiusIntegerAttributeParser(12);
        public static readonly RadiusEnumAttributeParser<FramedCompression> FramedCompression = new RadiusEnumAttributeParser<FramedCompression>(13);
        public static readonly RadiusIPAddressAttributeParser LoginIPHost = new RadiusIPAddressAttributeParser(14);
        public static readonly RadiusEnumAttributeParser<LoginService> LoginService = new RadiusEnumAttributeParser<LoginService>(15);
        public static readonly RadiusIntegerAttributeParser LoginTCPPort = new RadiusIntegerAttributeParser(16);
        public static readonly RadiusStringAttributeParser ReplyMessage = new RadiusStringAttributeParser(18);
        public static readonly RadiusStringAttributeParser CallbackNumber = new RadiusStringAttributeParser(19);
        public static readonly RadiusStringAttributeParser CallbackId = new RadiusStringAttributeParser(20);
        public static readonly RadiusStringAttributeParser FramedRoute = new RadiusStringAttributeParser(22);
        public static readonly RadiusIPAddressAttributeParser FramedIPXNetwork = new RadiusIPAddressAttributeParser(23);
        public static readonly RadiusBinaryAttributeParser State = new RadiusBinaryAttributeParser(24);
        public static readonly RadiusBinaryAttributeParser Class = new RadiusBinaryAttributeParser(25);
        public static readonly RadiusBinaryAttributeParser VendorSpecific = new RadiusBinaryAttributeParser(26);
        public static readonly RadiusIntegerAttributeParser SessionTimeout = new RadiusIntegerAttributeParser(27);
        public static readonly RadiusIntegerAttributeParser IdleTimeout = new RadiusIntegerAttributeParser(28);
        public static readonly RadiusEnumAttributeParser<TerminationAction> TerminationAction = new RadiusEnumAttributeParser<TerminationAction>(29);
        public static readonly RadiusStringAttributeParser CalledStationId = new RadiusStringAttributeParser(30);
        public static readonly RadiusStringAttributeParser CallingStationId = new RadiusStringAttributeParser(31);
        public static readonly RadiusStringAttributeParser NASIdentifier = new RadiusStringAttributeParser(32);
        public static readonly RadiusBinaryAttributeParser ProxyState = new RadiusBinaryAttributeParser(33);
        public static readonly RadiusStringAttributeParser LoginLATService = new RadiusStringAttributeParser(34);
        public static readonly RadiusStringAttributeParser LoginLATNode = new RadiusStringAttributeParser(35);
        public static readonly RadiusBinaryAttributeParser LoginLATGroup = new RadiusBinaryAttributeParser(36);
        public static readonly RadiusIntegerAttributeParser FramedAppleTalkLink = new RadiusIntegerAttributeParser(37);
        public static readonly RadiusIntegerAttributeParser FramedAppleTalkNetwork = new RadiusIntegerAttributeParser(38);
        public static readonly RadiusStringAttributeParser FramedAppleTalkZone = new RadiusStringAttributeParser(39);
        public static readonly RadiusEnumAttributeParser<AcctStatusType> AcctStatusType = new RadiusEnumAttributeParser<AcctStatusType>(40);
        public static readonly RadiusIntegerAttributeParser AcctDelayTime = new RadiusIntegerAttributeParser(41);
        public static readonly RadiusIntegerAttributeParser AcctInputOctets = new RadiusIntegerAttributeParser(42);
        public static readonly RadiusIntegerAttributeParser AcctOutputOctets = new RadiusIntegerAttributeParser(43);
        public static readonly RadiusStringAttributeParser AcctSessionId = new RadiusStringAttributeParser(44);
        public static readonly RadiusEnumAttributeParser<AcctAuthentic> AcctAuthentic = new RadiusEnumAttributeParser<AcctAuthentic>(45);
        public static readonly RadiusIntegerAttributeParser AcctSessionTime = new RadiusIntegerAttributeParser(46);
        public static readonly RadiusIntegerAttributeParser AcctInputPackets = new RadiusIntegerAttributeParser(47);
        public static readonly RadiusIntegerAttributeParser AcctOutputPackets = new RadiusIntegerAttributeParser(48);
        public static readonly RadiusEnumAttributeParser<AcctTerminateCause> AcctTerminateCause = new RadiusEnumAttributeParser<AcctTerminateCause>(49);
        public static readonly RadiusStringAttributeParser AcctMultiSessionId = new RadiusStringAttributeParser(50);
        public static readonly RadiusIntegerAttributeParser AcctLinkCount = new RadiusIntegerAttributeParser(51);
        public static readonly RadiusIntegerAttributeParser AcctInputGigawords = new RadiusIntegerAttributeParser(52);
        public static readonly RadiusIntegerAttributeParser AcctOutputGigawords = new RadiusIntegerAttributeParser(53);
        public static readonly RadiusDateTimeAttributeParser EventTimestamp = new RadiusDateTimeAttributeParser(55);
        public static readonly RadiusBinaryAttributeParser CHAPChallenge = new RadiusBinaryAttributeParser(60);
        public static readonly RadiusEnumAttributeParser<NASPortType> NASPortType = new RadiusEnumAttributeParser<NASPortType>(61);
        public static readonly RadiusIntegerAttributeParser PortLimit = new RadiusIntegerAttributeParser(62);
        public static readonly RadiusIntegerAttributeParser LoginLATPort = new RadiusIntegerAttributeParser(63);
        public static readonly RadiusIntegerAttributeParser PasswordRetry = new RadiusIntegerAttributeParser(75);
        public static readonly RadiusEnumAttributeParser<Prompt> Prompt = new RadiusEnumAttributeParser<Prompt>(76);
        public static readonly RadiusStringAttributeParser ConnectInfo = new RadiusStringAttributeParser(77);
        public static readonly RadiusBinaryAttributeParser ConfigurationToken = new RadiusBinaryAttributeParser(78);
        public static readonly RadiusBinaryAttributeParser EAPMessage = new RadiusBinaryAttributeParser(79);
        public static readonly RadiusBinaryAttributeParser MessageAuthenticator = new RadiusBinaryAttributeParser(80);
        public static readonly RadiusIntegerAttributeParser AcctInterimInterval = new RadiusIntegerAttributeParser(85);
        public static readonly RadiusStringAttributeParser NASPortId = new RadiusStringAttributeParser(87);
        public static readonly RadiusStringAttributeParser FramedPool = new RadiusStringAttributeParser(88);
        public static readonly RadiusIPAddressAttributeParser NASIPv6Address = new RadiusIPAddressAttributeParser(95, true);
        public static readonly RadiusBinaryAttributeParser FramedInterfaceId = new RadiusBinaryAttributeParser(96);
        public static readonly RadiusBinaryAttributeParser FramedIPv6Prefix = new RadiusBinaryAttributeParser(97);
        public static readonly RadiusIPAddressAttributeParser LoginIPv6Host = new RadiusIPAddressAttributeParser(98, true);
        public static readonly RadiusStringAttributeParser FramedIPv6Route = new RadiusStringAttributeParser(99);
        public static readonly RadiusStringAttributeParser FramedIPv6Pool = new RadiusStringAttributeParser(100);
    }

    #endregion
}
