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
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Text;

namespace Aufbauwerk.Surfstation.Server
{
    /// <summary>
    /// Static class containing extension methods for an <see cref="Image"/> object.
    /// </summary>
    static class Imaging
    {
        /// <summary>
        /// Scales the current <see cref="Image"/> to a given size maintaining the aspect ratio.
        /// </summary>
        /// <param name="image">The current image.</param>
        /// <param name="width">The maximum width.</param>
        /// <param name="height">The maximum height.</param>
        /// <param name="format">The <see cref="PixelFormat"/> for the zoomed image. If omitted, the original format will be used.</param>
        /// <returns>A new <see cref="Image"/> object containing the zoomed current image.</returns>
        public static Image Zoom(this Image image, int width, int height, PixelFormat format = PixelFormat.DontCare)
        {
            var factor = Math.Min((float)width / (float)image.Width, (float)height / (float)image.Height);
            width = (int)(image.Width * factor);
            height = (int)(image.Height * factor);
            var zoomed = new Bitmap(width, height, format == PixelFormat.DontCare ? image.PixelFormat : format);
            using (var gc = Graphics.FromImage(zoomed))
            {
                gc.Clear(Color.Transparent);
                gc.DrawImage(image, 0, 0, width, height);
            }
            return zoomed;
        }

        /// <summary>
        /// Converts the current <see cref="Image"/> into an OLE object byte array that can be used in Microsoft Access tables.
        /// </summary>
        /// <param name="image">The current image.</param>
        /// <param name="name">The optional name of the OLE object.</param>
        /// <param name="progId">The optional ProgId of the editor that should be used for the OLE object. Only meaningful if <paramref name="modifiable"/> is <c>true</c>.</param>
        /// <param name="dde">The optional DDE topic to be used for communicating with the editor.</param>
        /// <param name="modifiable">If <c>true</c>, the image is essentially stored twice making it modifiable within Access. This of course doubles the resulting array's size.</param>
        /// <returns>A byte array containing the OLE representation of the current image.</returns>
        public static byte[] ToOleObject(this Image image, string name = "Bitmap Image", string progId = "Paint.Picture", string dde = "PBrush", bool modifiable = true)
        {
            var nameBytes = Encoding.Default.GetBytes(name + "\0");
            var progIdBytes = Encoding.Default.GetBytes(progId + "\0");
            var ddeBytes = Encoding.Default.GetBytes(dde + "\0");
            using (var imageStream = new MemoryStream())
            using (var stream = new MemoryStream())
            {
                image.Save(imageStream, ImageFormat.Bmp);
                var writer = new BinaryWriter(stream, Encoding.Default);
                #region Header (Access)
                writer.Write((ushort)0x1c15); // Signature
                writer.Write((ushort)(20 + nameBytes.Length + progIdBytes.Length)); // HeaderSize
                writer.Write((uint)2); // ObjectType (OT_EMBEDDED)
                writer.Write((ushort)nameBytes.Length); // NameLen
                writer.Write((ushort)progIdBytes.Length); // ClassLen
                writer.Write((ushort)20); // NameOffset
                writer.Write((ushort)(20 + nameBytes.Length)); // ClassOffset
                writer.Write((uint)0xFFFFFFFF); // ObjectSize
                writer.Write(nameBytes); // Name
                writer.Write(progIdBytes); // Class
                #endregion
                #region Data (EmbeddedObject)
                #region Header (ObjectHeader)
                writer.Write((uint)0x00000501); // OLEVersion
                writer.Write((uint)2); // FormatID (EmbeddedObject)
                writer.Write((int)ddeBytes.Length); // ClassName.Length
                writer.Write(ddeBytes); // ClassName.String
                writer.Write((int)0); // TopicName.Length
                writer.Write((int)0); // ItemName.Length
                #endregion
                #region Native Data
                if (modifiable)
                {
                    writer.Write((int)imageStream.Length); // NativeDataSize
                    writer.Write(imageStream.GetBuffer(), 0, (int)imageStream.Length); // NativeData
                }
                else
                {
                    writer.Write((int)1); // NativeDataSize
                    writer.Write((byte)0); // NativeData
                }
                #endregion
                #region Presentation (DIBPresentationObject)
                #region Header (StandardPresentationObject)
                #region Header (PresentationObjectHeader)
                writer.Write((uint)0x00000501); // OLEVersion
                writer.Write((uint)5); // FormatID (ClassName present)
                writer.Write((int)4); // ClassName.Length
                writer.Write(new byte[] { 0x44, 0x49, 0x42, 0x00 }); // ClassName.String
                #endregion
                #region Dimensions
                writer.Write((int)Math.Round(image.Width / image.HorizontalResolution * 2540f)); // Width
                writer.Write((int)-Math.Round(image.Height / image.VerticalResolution * 2540f)); // Height
                #endregion
                #endregion
                writer.Write((int)(imageStream.Length - 14)); // PresentationDataSize
                writer.Write(imageStream.GetBuffer(), 14, (int)(imageStream.Length - 14)); // DIB (DeviceIndependentBitmap)
                #endregion
                #endregion
                writer.Write((uint)0xFE05AD00); // Signature
                return stream.ToArray();
            }
        }
    }
}
