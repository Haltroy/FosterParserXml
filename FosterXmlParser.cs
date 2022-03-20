using System.Collections.Generic;
using System.Xml;

namespace LibFoster.Modules
{
    /// <summary>
    /// XML parser for Foster.
    /// </summary>
    public class FosterXmlParser : FosterParserBase
    {
        public override string ParserName => "xml";

        public override void ParseInfo(object info, Foster foster)
        {
            if (info is string)
            {
                ParseXml(info as string, foster);
            }
            else if (info is System.IO.Stream)
            {
                var infoStream = info as System.IO.Stream;
                var header = GetHeader();
                infoStream.Position = header.Length;
                System.IO.StreamReader reader = new System.IO.StreamReader(infoStream);
                ParseXml(reader.ReadToEnd(), foster);
            }
            else
            {
                throw new TypeErrorException(ParserName);
            }
        }

        public override System.IO.Stream ToParsable(Foster foster)
        {
            var stream = new System.IO.MemoryStream
            {
                Position = 0
            };
            var header = GetHeader();
            stream.Write(header, 0, header.Length);
            var title = "<?xml version=\"1.0\" encoding=\"utf-16\" ?>"
                        + System.Environment.NewLine
                        + "<root>"
                        + System.Environment.NewLine
                        + "<Name>"
                        + foster.Name
                        + "</Name>"
                        + System.Environment.NewLine
                        + "<Version>"
                        + foster.LatestVer
                        + "</Version>"
                        + System.Environment.NewLine;
            if (foster.Dependencies != null && foster.Dependencies.Count > 0)
            {
                for (int i = 0; i < foster.Dependencies.Count; i++)
                {
                    title += "<Dependency Name=\"" + foster.Dependencies[i].Name + "\" Url=\"" + foster.Dependencies[i].URL.ToString() + "\" />" + System.Environment.NewLine;
                }
            }

            title += "<Versions>"
                        + System.Environment.NewLine;
            for (int i = 0; i < foster.Versions.Count; i++)
            {
                var version = foster.Versions[i];
                title += "<Version>"
                         + System.Environment.NewLine
                         + "<Name>"
                         + version.Name
                         + "</Name>"
                         + System.Environment.NewLine
                         + "<ID>"
                         + version.ID
                         + "</ID>"
                         + System.Environment.NewLine
                         + (version.BasedVersion != null ? "<Based>" + (version.BasedVersion is int ınt ? ınt : (version.BasedVersion as Foster_Version).ID) + "</Based>" + System.Environment.NewLine : "")
                         + ((version.Flags is null || version.Flags.Length <= 0) ? "" : "<Flags>" + string.Join(";", version.Flags) + "</Flags>" + System.Environment.NewLine)
                         + (version.LTS ? "<LTS>" + version.LTSRevokeDate + "<LTS>" + System.Environment.NewLine : "");
                if (version.Dependencies != null && version.Dependencies.Count > 0)
                {
                    for (int di = foster.Dependencies.Count - 1; di >= 0; di--)
                    {
                        title += "<Dependency Name=\"" + version.Dependencies[di].Dependency.Name + "\" Version=\"" + version.Dependencies[di].RequiredVerID + "\" />" + System.Environment.NewLine;
                    }
                }
                title += "<Archs>"
                + System.Environment.NewLine;
                for (int ai = 0; ai < version.Archs.Count; ai++)
                {
                    var arch = version.Archs[ai];
                    title += "<Arch>"
                          + System.Environment.NewLine
                          + "<Arch>"
                          + arch.Arch
                          + "</Arch>"
                          + System.Environment.NewLine
                          + "<DiskSize>"
                          + arch.DiskSize
                          + "</DiskSize>"
                          + System.Environment.NewLine
                          + "<DownloadSize>"
                          + arch.DownloadSize
                          + "</DownloadSize>"
                          + System.Environment.NewLine
                          + "<Mirrors>"
                          + System.Environment.NewLine;
                    for (int ui = 0; ui < arch.Url.Length; ui++)
                    {
                        title += "<Mirror>" + arch.Url[ui].ToString() + "</Mirror>" + System.Environment.NewLine;
                    }
                    title += "</Mirrors>" + System.Environment.NewLine;
                    if (arch.Hashes.Count > 0)
                    {
                        for (int hi = 0; hi < arch.Hashes.Count; hi++)
                        {
                            var hash = arch.Hashes[hi];
                            title += "<Hash Algorithm=\"" + hash.AlgorithmShortName + "\">" + hash.Hash + "</Hash>" + System.Environment.NewLine;
                        }
                    }
                    title += "</Arch>" + System.Environment.NewLine;
                }
                title += "</Archs>" + System.Environment.NewLine + "</Version>" + System.Environment.NewLine;
            }
            title = Tools.BeautifyXML(title + "</Versions>" + System.Environment.NewLine + "</root>");
            var byteList = new List<byte>();
            byteList.AddRange(System.Text.Encoding.Unicode.GetBytes(title));
            for (int i = 0; i < byteList.Count; i++)
            {
                if (byteList[i] != 0x00)
                {
                    stream.WriteByte(byteList[i]);
                }
            }
            return stream;
        }

        private void ParseVersion(XmlNode vernode, Foster_Version version, Foster foster)
        {
            List<string> verapplied = new List<string>();
            for (int i = 0; i < vernode.ChildNodes.Count; i++)
            {
                XmlNode node = vernode.ChildNodes[i];
                if (!verapplied.Contains(node.Name.ToLowerEnglish()))
                {
                    verapplied.Add(node.Name.ToLowerEnglish());
                    switch (node.Name.ToLowerEnglish())
                    {
                        case "name":
                            version.Name = node.InnerXml.XmlToString();
                            break;

                        case "dep":
                        case "dependency":
                            Foster_Dependency dep = new Foster_Dependency();
                            if (node.Attributes["Name"] == null)
                            {
                                throw new System.Exception("The dependency node does not have the name attribute in verison \"" + version.ID + "\".");
                            }
                            if (node.Attributes["Version"] == null)
                            {
                                throw new System.Exception("The dependency node does not have the version attribute in version \"" + version.ID + "\".");
                            }
                            var depL = foster.Dependencies.FindAll(it => string.Equals(it.Name, node.Attributes["Name"].Value));
                            if (depL == null || depL.Count <= 0)
                            {
                                throw new System.Exception("The dependency node does not have a matching dependency in version \"" + version.ID + "\".");
                            }
                            else
                            {
                                dep.Dependency = depL[0];
                            }
                            dep.RequiredVerID = int.Parse(node.Attributes["Version"].Value);
                            version.Dependencies.Add(dep);
                            break;

                        case "id":
                            version.ID = int.Parse(node.InnerXml.XmlToString());
                            break;

                        case "flags":
                            version.Flags = node.InnerXml.XmlToString().Split(';');
                            break;

                        case "based":
                            version.BasedVersion = foster.GetVersion(int.Parse(node.InnerXml.XmlToString())) ?? (object)int.Parse(node.InnerXml.XmlToString());
                            break;

                        case "architectures":
                        case "archs":
                            for (int _i = 0; _i < node.ChildNodes.Count; _i++)
                            {
                                XmlNode subnode = node.ChildNodes[_i];
                                if (subnode.Name.ToLowerEnglish() == "arch")
                                {
                                    Foster_Arch arch = new Foster_Arch(version);
                                    for (int ai = 0; ai < subnode.ChildNodes.Count; ai++)
                                    {
                                        XmlNode subsubnode = subnode.ChildNodes[ai];
                                        switch (subsubnode.Name.ToLowerEnglish())
                                        {
                                            case "hash":
                                                if (subsubnode.Attributes["Algorithm"] != null && !string.IsNullOrWhiteSpace(subsubnode.InnerXml))
                                                {
                                                    Foster_Hash hash = new Foster_Hash
                                                    {
                                                        Hash = subsubnode.InnerXml.XmlToString(),
                                                        AlgorithmShortName = subsubnode.Attributes["Algorithm"].Value.XmlToString().ToLowerEnglish()
                                                    };
                                                    switch (hash.AlgorithmShortName)
                                                    {
                                                        case "md5": hash.Algorithm = System.Security.Cryptography.MD5.Create(); break;
                                                        case "sha256": hash.Algorithm = System.Security.Cryptography.SHA256.Create(); break;
                                                        case "sha1": hash.Algorithm = System.Security.Cryptography.SHA1.Create(); break;
                                                        case "sha384": hash.Algorithm = System.Security.Cryptography.SHA384.Create(); break;
                                                        case "sha512": hash.Algorithm = System.Security.Cryptography.SHA512.Create(); break;
                                                        case "hmacmd5": hash.Algorithm = System.Security.Cryptography.HMACMD5.Create(); break;
                                                        case "hmacsha1": hash.Algorithm = System.Security.Cryptography.HMACSHA1.Create(); break;
                                                        case "hmacsha256": hash.Algorithm = System.Security.Cryptography.HMACSHA256.Create(); break;
                                                        case "hmacsha384": hash.Algorithm = System.Security.Cryptography.HMACSHA384.Create(); break;
                                                        case "hmacsha512": hash.Algorithm = System.Security.Cryptography.HMACSHA512.Create(); break;
                                                    }
                                                    arch.Hashes.Add(hash);
                                                }
                                                break;

                                            case "arch":

                                                arch.Arch = subsubnode.InnerXml.XmlToString();
                                                break;

                                            case "urls":
                                            case "mirrors":

                                                List<string> urls = new List<string>();
                                                foreach (XmlNode urlnode in subsubnode.ChildNodes)
                                                {
                                                    if (urlnode.Name.ToLowerEnglish() == "url" || urlnode.Name.ToLowerEnglish() == "mirror")
                                                    {
                                                        urls.Add(urlnode.InnerXml.XmlToString());
                                                    }
                                                }
                                                arch.Url = urls.ToArray();
                                                break;

                                            case "url":
                                            case "mirror":

                                                List<string> _urls = new List<string>();
                                                if (arch.Url != null)
                                                {
                                                    _urls.AddRange(arch.Url);
                                                }
                                                _urls.Add(subsubnode.InnerXml.XmlToString());
                                                arch.Url = _urls.ToArray();
                                                break;

                                            case "disksize":
                                                arch.DiskSize = long.Parse(subsubnode.InnerXml.XmlToString(), System.Globalization.NumberStyles.AllowLeadingSign);
                                                break;

                                            case "downloadsize":
                                                arch.DownloadSize = long.Parse(subsubnode.InnerXml.XmlToString());
                                                break;
                                        }
                                    }
                                    arch.IsDelta = version.BasedVersion != null;
                                    version.Archs.Add(arch);
                                }
                            }
                            break;

                        case "lts":
                            version.LTS = true;
                            version.LTSRevokeDate = node.InnerXml.XmlToString();
                            break;
                    }
                }
            }
        }

        private void ParseXml(string xml, Foster foster)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xml);
            XmlNode rootNode = doc.FindRoot();
            List<string> applied = new List<string>();
            for (int i = 0; i < rootNode.ChildNodes.Count; i++)
            {
                bool exitLoop = false;
                XmlNode node = rootNode.ChildNodes[i];
                switch (node.Name.ToLowerEnglish())
                {
                    case "mirror":
                        if (applied.Contains(node.Name.ToLowerEnglish()))
                        {
                            break;
                        }
                        applied.Add(node.Name.ToLowerEnglish());
                        foster.Log("Mirror found.");
                        if (node.Attributes["URL"] == null)
                        {
                            foster.Log("Mirror link was null.", LogLevel.Error);
                        }
                        else
                        {
                            foster.URL = node.Attributes["URL"].Value.XmlToString();
                            foster.Log("Mirrored to \"" + foster.URL + "\".");
                            foster.LoadFromUrl();
                            exitLoop = true;
                            break;
                        }
                        return;

                    case "dep":
                    case "dependency":
                        Foster_Dependency dep = new Foster_Dependency();
                        if (node.Attributes["Url"] == null)
                        {
                            throw new System.Exception("The dependency node does not have the URL attribute.");
                        }
                        if (node.Attributes["Name"] == null)
                        {
                            throw new System.Exception("The dependency node does not have the Name attribute.");
                        }
                        var _dep = new Foster(node.Attributes["Url"].Value, foster) { IsSkeleton = foster.IsSkeleton };
                        if (!foster.IsSkeleton) { _dep.LoadUrlSync(); }
                        _dep.Name = node.Attributes["Name"].Value;
                        break;

                    case "name":
                        if (applied.Contains(node.Name.ToLowerEnglish()))
                        {
                            break;
                        }
                        applied.Add(node.Name.ToLowerEnglish());
                        if (string.IsNullOrWhiteSpace(node.InnerXml))
                        {
                            foster.Log("Name was null.");
                        }
                        else
                        {
                            foster.Name = node.InnerXml.XmlToString();
                        }
                        break;

                    case "version":
                        if (applied.Contains(node.Name.ToLowerEnglish()))
                        {
                            break;
                        }
                        applied.Add(node.Name.ToLowerEnglish());
                        if (string.IsNullOrWhiteSpace(node.InnerXml))
                        {
                            foster.Log("Version InnerXML is empty.", LogLevel.Error);
                            return;
                        }
                        foster.LatestVer = int.Parse(node.InnerXml.XmlToString());
                        break;

                    case "versions":
                        if (applied.Contains(node.Name.ToLowerEnglish()))
                        {
                            break;
                        }
                        applied.Add(node.Name.ToLowerEnglish());
                        for (int _i = 0; _i < node.ChildNodes.Count; _i++)
                        {
                            Foster_Version ver = new Foster_Version(foster);
                            ParseVersion(node.ChildNodes[_i], ver, foster);
                            if (!foster.Versions.Contains(ver))
                            {
                                foster.Versions.Add(ver);
                            }
                        }
                        foster.Versions.Sort((x, y) => x.ID.CompareTo(y.ID));
                        break;

                    default:
                        break;
                }
                if (exitLoop) { break; }
            }
        }
    }
}