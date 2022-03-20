/*

Copyright © 2021 - 2022 haltroy

Use of this source code is governed by a MIT License that can be found in github.com/haltroy/Foster/blob/master/COPYING

*/

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace LibFoster.Modules
{
    /// <summary>
    /// Minimal version of the HTAlt's Tools class.
    /// </summary>
    internal static class Tools
    {
        #region Strings

        /// <summary>
        /// Detects if user can access <paramref name="dir"/> by try{} method.
        /// </summary>
        /// <param name="dir">Directory</param>
        /// <returns><c>true</c> if can access to folder, <c>false</c> if user has no access to <paramref name="dir"/> and throws <see cref="Exception"/> on other scenarios.</returns>
        public static bool HasWriteAccess(this string dir)
        {
            try
            {
                string random = "RANDOM_" + GenerateRandomText(17);
                WriteFile(dir + "\\HTALT.TEST", random, System.Text.Encoding.Unicode);
                string file = ReadFile(dir + "\\HTPACKER.TEST", System.Text.Encoding.Unicode);
                System.IO.File.Delete(dir + "\\HTPACKER.TEST");
                if (file == random)
                {
                    return true;
                }
                else
                {
                    throw new Exception("Test file \"" + dir + "\\HTPACKER.TEST" + "\" was altered.");
                }
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        /// <summary>
        /// Gets the directory size.
        /// </summary>
        /// <param name="d"><see cref="string"/></param>
        /// <returns><see cref="long"/></returns>
        public static long GetDirSize(this string d)
        {
            return new DirectoryInfo(d).GetSize();
        }

        /// <summary>
        /// Gets the directory size.
        /// </summary>
        /// <param name="d"><see cref="DirectoryInfo"/></param>
        /// <returns><see cref="long"/></returns>
        public static long GetSize(this DirectoryInfo d)
        {
            long size = 0;
            // Add file sizes.
            FileInfo[] fis = d.GetFiles();
            foreach (FileInfo fi in fis)
            {
                size += fi.Length;
            }
            // Add subdirectory sizes.
            DirectoryInfo[] dis = d.GetDirectories();
            foreach (DirectoryInfo di in dis)
            {
                size += GetSize(di);
            }
            return size;
        }

        /// <summary>
        /// Finds the root node of <paramref name="doc"/>.
        /// </summary>
        /// <param name="doc">the <see cref="XmlNode"/> (probably <seealso cref="XmlDocument.DocumentElement"/>) to search on.</param>
        /// <returns>a <see cref="System.Xml.XmlNode"/> which represents as the root node.</returns>
        public static System.Xml.XmlNode FindRoot(this System.Xml.XmlNode doc)
        {
            System.Xml.XmlNode found = null;
            if (ToLowerEnglish(doc.Name) == "root")
            {
                found = doc;
            }
            else
            {
                for (int i = 0; i < doc.ChildNodes.Count; i++)
                {
                    System.Xml.XmlNode node = doc.ChildNodes[i];
                    if (ToLowerEnglish(node.Name) == "root")
                    {
                        found = node;
                    }
                }
            }
            return found;
        }

        /// <summary>
        /// Tells if the <paramref name="node"/> is a comment node.
        /// </summary>
        /// <param name="node"><see cref="XmlNode"/></param>
        /// <returns><see cref="bool"/></returns>
        public static bool NodeIsComment(this System.Xml.XmlNode node)
        {
            return node.OuterXml.StartsWith("<!--");
        }

        /// <summary>
        /// Minimalizes a byte to a readable size. Limited to 2 gigabytes.
        /// </summary>
        /// <param name="baytValue"><see cref="int"/></param>
        /// <returns><see cref="string"/></returns>
        public static string ByteToReadable(this int baytValue, bool useKibi = true)
        {
            return ByteToReadable((long)baytValue, useKibi);
        }

        /// <summary>
        /// Minimalizes a byte to a readable size.
        /// </summary>
        /// <param name="baytValue"><see cref="long"/></param>
        /// <returns><see cref="string"/></returns>
        public static string ByteToReadable(this long baytValue, bool useKibi = true)
        {
            if (useKibi ? (baytValue < 1024) : (baytValue < 1000))
            {
                return baytValue + " b";
            }
            else if (useKibi ? (baytValue < 1048576) : (baytValue < 1000000))
            {
                return (baytValue / (useKibi ? 1024 : 1000)) + " " + (useKibi ? "KiB" : "KB");
            }
            else if (useKibi ? (baytValue < 1073741824) : (baytValue < 1000000000))
            {
                return (baytValue / (useKibi ? 1048576 : 1000000)) + " " + (useKibi ? "MiB" : "MB");
            }
            else if (useKibi ? (baytValue < 1099511627776) : (baytValue < 1000000000000))
            {
                return (baytValue / (useKibi ? 1073741824 : 1000000000)) + " " + (useKibi ? "GiB" : "GB");
            }
            else
            {
                return (baytValue / (useKibi ? 1099511627776 : 1000000000000)) + " " + (useKibi ? "TiB" : "TB");
            }
        }

        /// <summary>
        /// Turns all characters to lowercase, using en-US culture information to avoid language-specific ToLower() errors such as:
        /// <para>Turkish: I &lt;-&gt; ı , İ &lt;-&gt; i</para>
        /// <para>English I &lt;-&gt; i</para>
        /// </summary>
        /// <param name="s"><see cref="string"/></param>
        /// <returns><see cref="string"/></returns>
        public static string ToLowerEnglish(this string s)
        {
            return s.ToLower(new System.Globalization.CultureInfo("en-US", false));
        }

        /// <summary>
        /// Finds the root node of <paramref name="doc"/>.
        /// </summary>
        /// <param name="doc">The XML document.</param>
        /// <returns>a <see cref="System.Xml.XmlNode"/> which represents as the root node.</returns>
        public static System.Xml.XmlNode FindRoot(this System.Xml.XmlDocument doc)
        {
            return FindRoot(doc.DocumentElement);
        }

        /// <summary>
        /// Converts XML-formatted string to <see cref="string"/>.
        /// </summary>
        /// <param name="innerxml">XML-formatted string</param>
        /// <returns>Formatted <paramref name="s"/>.</returns>
        public static string XmlToString(this string innerxml)
        {
            return innerxml.Replace("&amp;", "&").Replace("&quot;", "\"").Replace("&apos;", "'").Replace("&lt;", "<").Replace("&gt;", ">");
        }

        /// <summary>
        /// Converts <paramref name="s"/> to <see cref="System.Xml"/> supported format.
        /// </summary>
        /// <param name="s"><see cref="string"/></param>
        /// <returns>Formatted <paramref name="s"/>.</returns>
        public static string ToXML(this string s)
        {
            return s.Replace("&", "&amp;").Replace("\"", "&quot;").Replace("'", "&apos;").Replace("<", "&lt;").Replace(">", "&gt;");
        }

        /// <summary>
        /// Prettifies XML code.
        /// Thanks to S M Kamran & Bakudan from StackOverflow
        /// https://stackoverflow.com/a/1123731
        /// </summary>
        /// <param name="xml">XML code</param>
        /// <returns>Prettified <paramref name="xml"/></returns>
        public static string BeautifyXML(this string xml)
        {
            System.IO.MemoryStream mStream = new System.IO.MemoryStream();
            System.Xml.XmlTextWriter writer = new System.Xml.XmlTextWriter(mStream, System.Text.Encoding.Unicode);
            System.Xml.XmlDocument document = new System.Xml.XmlDocument();

            // Load the XmlDocument with the XML.
            document.LoadXml(xml);

            writer.Formatting = System.Xml.Formatting.Indented;

            // Write the XML into a formatting XmlTextWriter
            document.WriteContentTo(writer);
            writer.Flush();
            mStream.Flush();

            // Have to rewind the MemoryStream in order to read
            // its contents.
            mStream.Position = 0;

            // Read MemoryStream contents into a StreamReader.
            System.IO.StreamReader sReader = new System.IO.StreamReader(mStream);

            // Extract the text from the StreamReader.
            string formattedXml = sReader.ReadToEnd();

            string result = formattedXml;
            mStream.Close();
            writer.Close();

            return result;
        }

        /// <summary>
        /// Generates a random text with random characters with length.
        /// </summary>
        /// <param name="length">Length of random text./param>
        /// <returns>Random characters in a string.</returns>
        public static string GenerateRandomText(int length = 17)
        {
            if (length == 0) { throw new ArgumentOutOfRangeException("\"length\" must be greater than 0."); }
            if (length < 0) { length *= -1; }
            if (length >= int.MaxValue) { throw new ArgumentOutOfRangeException("\"length\" must be smaller than the 32-bit integer limit."); }
            StringBuilder builder = new StringBuilder();
            Enumerable
               .Range(65, 26)
                .Select(e => ((char)e).ToString())
                .Concat(Enumerable.Range(97, 26).Select(e => ((char)e).ToString()))
                .Concat(Enumerable.Range(0, length - 1).Select(e => e.ToString()))
                .OrderBy(e => Guid.NewGuid())
                .Take(length)
                .ToList().ForEach(e => builder.Append(e));
            return builder.ToString();
        }

        #endregion Strings

        #region Read File

        /// <summary>
        /// Reads a file without locking it.
        /// </summary>
        /// <param name="fileLocation">Location of the file.</param>
        /// <param name="encode">Rules for reading the file.</param>
        /// <returns>Text inside the file.</returns>
        public static string ReadFile(string fileLocation, Encoding encode)
        {
            StreamReader sr = new StreamReader(ReadFile(fileLocation), encode);
            string result = sr.ReadToEnd();
            sr.Close();
            return result;
        }

        /// <summary>
        /// Reads a file without locking it.
        /// </summary>
        /// <param name="fileLocation">Location of the file.</param>
        /// <param name="ignored">Rules for reading the file.</param>
        /// <returns>Bytes inside the file.</returns>
#pragma warning disable IDE0060 // Remove unused parameter

        public static byte[] ReadFile(string fileLocation, bool ignored = false)
#pragma warning restore IDE0060 // Remove unused parameter
        {
            MemoryStream ms = new MemoryStream();
            ReadFile(fileLocation).CopyTo(ms);
            return ms.ToArray();
        }

        /// <summary>
        /// Reads a file without locking it.
        /// </summary>
        /// <param name="fileLocation">Location of the file.</param>
        /// <returns>File stream containing file information.</returns>
        public static Stream ReadFile(string fileLocation)
        {
            FileStream fs = new FileStream(fileLocation, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return fs;
        }

        #endregion Read File

        #region Write File

        /// <summary>
        /// Creates and writes a file without locking it.
        /// </summary>
        /// <param name="fileLocation">Location of the file.</param>
        /// <param name="input">Text to write on.</param>
        /// <param name="encode">Rules to follow while writing.</param>
        /// <returns><c>true</c> if successfully writes to file, otherwise throws an exception.</returns>
        public static void WriteFile(string fileLocation, string input, Encoding encode)
        {
            if (!Directory.Exists(new FileInfo(fileLocation).DirectoryName)) { Directory.CreateDirectory(new FileInfo(fileLocation).DirectoryName); }
            if (File.Exists(fileLocation))
            {
                File.Delete(fileLocation);
            }
            File.Create(fileLocation).Dispose();
            if (ReadFile(fileLocation, encode) != input)
            {
                FileStream writer = new FileStream(fileLocation, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                writer.Write(encode.GetBytes(input), 0, encode.GetBytes(input).Length);
                writer.Close();
            }
        }

        /// <summary>
        /// Creates and writes a file without locking it.
        /// </summary>
        /// <param name="fileLocation">Location of the file.</param>
        /// <param name="input">Bytes to write on.</param>
        /// <returns><c>true</c> if successfully writes to file, otherwise throws an exception.</returns>
        public static void WriteFile(string fileLocation, byte[] input)
        {
            if (!Directory.Exists(new FileInfo(fileLocation).DirectoryName)) { Directory.CreateDirectory(new FileInfo(fileLocation).DirectoryName); }
            if (File.Exists(fileLocation))
            {
                File.Delete(fileLocation);
            }
            File.Create(fileLocation).Dispose();
            if (ReadFile(fileLocation, true) != input)
            {
                FileStream writer = new FileStream(fileLocation, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                writer.Write(input, 0, input.Length);
                writer.Close();
            }
        }

        /// <summary>
        /// Creates and writes a file without locking it.
        /// </summary>
        /// <param name="fileLocation">Location of the file.</param>
        /// <param name="stream">Stream to write on.</param>
        /// <returns><c>true</c> if successfully writes to file, otherwise throws an exception.</returns>
        public static void WriteFile(string fileLocation, Stream stream)
        {
            if (!Directory.Exists(new FileInfo(fileLocation).DirectoryName)) { Directory.CreateDirectory(new FileInfo(fileLocation).DirectoryName); }
            if (File.Exists(fileLocation))
            {
                File.Delete(fileLocation);
            }
            File.Create(fileLocation).Dispose();
            if (ReadFile(fileLocation) != stream)
            {
                FileStream writer = new FileStream(fileLocation, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                stream.CopyTo(writer);
                writer.Close();
            }
        }

        #endregion Write File

        #region Verify File

        /// <summary>
        /// Converts a byte array to <see cref="string"/>.
        /// </summary>
        /// <param name="bytes"><see cref="byte"/> <seealso cref="Array"/>.</param>
        /// <returns><see cref="string"/></returns>
        public static string BytesToString(byte[] bytes)
        {
            string result = "";
            for (int i = 0; i < bytes.Length; i++)
            {
                result += bytes[i].ToString("x2");
            }
            return result;
        }

        /// <summary>
        /// Verifies a file with <see cref="System.Security.Cryptography.MD5"/> and <seealso cref="System.Security.Cryptography.SHA256"/> methods.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file">File location.</param>
        /// <param name="hash">File's supposedly hash.</param>
        /// <returns><see cref="bool"/></returns>
        public static bool VerifyFile(System.Security.Cryptography.HashAlgorithm algorithm, System.IO.Stream stream, string hash)
        {
            return string.Equals(GetHash(algorithm, stream), hash);
        }

        /// <summary>
        /// Verifies a file with <see cref="System.Security.Cryptography.MD5"/> and <seealso cref="System.Security.Cryptography.SHA256"/> methods.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file">File location.</param>
        /// <param name="hash">File's supposedly hash.</param>
        /// <returns><see cref="bool"/></returns>
        public static bool VerifyFile(System.Security.Cryptography.HashAlgorithm algorithm, System.IO.Stream stream, byte[] hash)
        {
            return System.Linq.Enumerable.SequenceEqual(GetHash(algorithm, stream), hash);
        }

        /// <summary>
        /// Verifies a file with <see cref="System.Security.Cryptography.MD5"/> and <seealso cref="System.Security.Cryptography.SHA256"/> methods.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file">File location.</param>
        /// <param name="hash">File's supposedly hash.</param>
        /// <returns><see cref="bool"/></returns>
        public static bool VerifyFile(System.Security.Cryptography.HashAlgorithm algorithm, string file, string hash)
        {
            return string.Equals(GetHash(algorithm, file), hash);
        }

        /// <summary>
        /// Verifies a file with <see cref="System.Security.Cryptography.MD5"/> and <seealso cref="System.Security.Cryptography.SHA256"/> methods.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file">File location.</param>
        /// <param name="hash">File's supposedly hash.</param>
        /// <returns><see cref="bool"/></returns>
        public static bool VerifyFile(System.Security.Cryptography.HashAlgorithm algorithm, string file, byte[] hash)
        {
            return System.Linq.Enumerable.SequenceEqual(GetHash(algorithm, file), hash);
        }

        /// <summary>
        /// Gets <see cref="System.Security.Cryptography.SHA256"/> of <paramref name="file"/>.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file">File location.</param>
        /// <param name="ignored">Ignored value.</param>
        /// <returns><see cref="string"/></returns>
#pragma warning disable IDE0060 // Remove unused parameter

        public static string GetHash(System.Security.Cryptography.HashAlgorithm algorithm, string file, bool ignored = false)
#pragma warning restore IDE0060 // Remove unused parameter
        {
            return BytesToString(GetHash(algorithm, file));
        }

        /// <summary>
        /// Gets the file hash of <paramref name="file"/> with <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file"><see cref="string"/></param>
        /// <returns><see cref="byte"/> <seealso cref="Array"/>.</returns>
        public static byte[] GetHash(System.Security.Cryptography.HashAlgorithm algorithm, string file)
        {
            return algorithm.ComputeHash(ReadFile(file));
        }

        /// <summary>
        /// Gets <see cref="System.Security.Cryptography.SHA256"/> of <paramref name="file"/>.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="file">File location.</param>
        /// <param name="ignored">Ignored value.</param>
        /// <returns><see cref="string"/></returns>
#pragma warning disable IDE0060 // Remove unused parameter

        public static string GetHash(System.Security.Cryptography.HashAlgorithm algorithm, System.IO.Stream stream, bool ignored = false)
#pragma warning restore IDE0060 // Remove unused parameter
        {
            return BytesToString(GetHash(algorithm, stream));
        }

        /// <summary>
        /// Gets the file hash of <paramref name="file"/> with <paramref name="algorithm"/>.
        /// </summary>
        /// <param name="algorithm"><see cref="System.Security.Cryptography.HashAlgorithm"/></param>
        /// <param name="stream"><see cref="System.IO.Stream"/></param>
        /// <returns><see cref="byte"/> <seealso cref="Array"/>.</returns>
        public static byte[] GetHash(System.Security.Cryptography.HashAlgorithm algorithm, System.IO.Stream stream)
        {
            return algorithm.ComputeHash(stream);
        }

        /// <summary>
        /// Return <c>true</c> if path directory is empty.
        /// </summary>
        /// <param name="path">Directory path to check.</param>
        /// <returns><c>true</c> if the directory is empty, otherwise <c>false</c>.</returns>
        public static bool IsDirectoryEmpty(string path)
        {
            if (Directory.Exists(path))
            {
                if (Directory.GetDirectories(path).Length > 0) { return false; } else { return true; }
            }
            else { return true; }
        }

        #endregion Verify File
    }
}