# FosterParserXml

This package adds XML parsing support to Foster.

# Usage

1. Install this package from NuGet or clone this repository and add Project Reference to your project.
2. In your project's starting void (mostly Program.cs Main() void) add `new Foster.Modules.FosterXmlParser.Register();`
3. You can now use Foster with XML format.

# Build
To build this package, .NET SDK must be installed. To build from command-line: `dotnet build`