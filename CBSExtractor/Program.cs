using CommandLine;
using CommandLine.Text;
using Microsoft.WindowsPhone.ImageUpdate.PkgCommon;
using Pri.LongPath;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace CBSExtractor
{
    class Program
    {
        static readonly string InternalName = Assembly.GetExecutingAssembly().GetName().Name;
        static readonly string FileVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
        static readonly string LegalCopyright = "Copyright (c) 2024";
        static readonly string CompanyName = "Fadil Fadz";
        static readonly string CurrentDirectory = Directory.GetCurrentDirectory();
        static readonly string TempDirectory = $"{Directory.GetCurrentDirectory()}\\temp";

        static string[] Packages { get; set; }
        static bool ThrowErrorAllowed { get; set; }

        static void Main(string[] args)
        {
            var parser = new Parser(with => with.CaseSensitive = false);
            var result = parser.ParseArguments<Options>(args);
            result.WithParsed(arguments =>
            {
                try
                {
                    string drive = string.Empty;
                    string output = string.Empty;

                    if (arguments.Drive.EndsWith("\\"))
                    {
                        drive = arguments.Drive.Remove(arguments.Drive.Length - 1);
                    }
                    else
                    {
                        drive = arguments.Drive;
                    }
                    if (arguments.Output.EndsWith("\\"))
                    {
                        output = arguments.Output.Remove(arguments.Output.Length - 1);
                    }
                    else
                    {
                        output = arguments.Output;
                    }
                    if (arguments.Filter != null && arguments.Filter != string.Empty)
                    {
                        if (arguments.Filter.EndsWith(';')) arguments.Filter = arguments.Filter.Remove(arguments.Filter.Length - 1);
                        var filters = arguments.Filter.Split(';');
                        Packages = new string[filters.Length];
                        for (int i = 0; i < filters.Length; i++)
                        {
                            try
                            {
                                Packages[i] = Directory.GetFiles($"{drive}\\Windows\\servicing\\Packages", $"{filters[i]}~*.mum", System.IO.SearchOption.TopDirectoryOnly)[0];
                            }
                            catch (Exception)
                            {
                                Packages[i] = filters[i];
                            }
                        }
                    }

                    Console.WriteLine($"{InternalName} {FileVersion}");
                    Console.WriteLine($"{LegalCopyright} - {CompanyName}");
                    Console.WriteLine("");

                    Logging($"Running the {InternalName} v{FileVersion}", LoggingOption.Information);

                    if (!Directory.Exists(drive) || !Directory.Exists(output))
                        throw new System.IO.DirectoryNotFoundException("The system cannot find the path specified.");

                    Console.WriteLine($"Source: {drive}\\");
                    Console.WriteLine($"Destination: {output}");
                    try
                    {
                        if (Packages.Count() > 0)
                            Console.WriteLine("Filter: True");
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("Filter: False");
                    }
                    Console.WriteLine($"Sign: {arguments.Sign}");
                    Console.WriteLine("");

                    if (Directory.Exists(TempDirectory))
                    {
                        var ex = ForceDeleteDirectory(TempDirectory);
                        if (ex != null)
                        {
                            Logging($"Failed to wipe the directory {TempDirectory}.", LoggingOption.Warning);
                            Logging($"{ex}", LoggingOption.Exception);
                        }
                    }

                    if (arguments.Filter == null)
                        Packages = Directory.GetFiles($"{drive}\\Windows\\servicing\\Packages", "*.mum", System.IO.SearchOption.TopDirectoryOnly);

                    Process process = new Process();
                    process.StartInfo.FileName = "certutil.exe";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.StartInfo.RedirectStandardError = true;
                    process.StartInfo.RedirectStandardInput = true;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.Arguments = "-delstore -user MY \"30 8c e4 36 9a 39 d5 8a 45 40 f9 f8 28 e9 25 97\"";
                    process.Start();
                    process.WaitForExit();
                    foreach (var certificate in Certificates)
                    {
                        GetResourceFile(certificate);
                        if (certificate.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                        {
                            process.StartInfo.Arguments = $"-p \"\" -user -importpfx \"{Path.GetTempPath()}Certificates\\{certificate}\" NoRoot";
                            process.Start();
                            process.WaitForExit();
                        }
                        else if (certificate == "OEM_Root_CA.cer" || certificate == "OEM_Root_CA2.cer")
                        {
                            process.StartInfo.Arguments = $"-addstore Root \"{Path.GetTempPath()}Certificates\\{certificate}\"";
                            process.Start();
                            process.WaitForExit();
                        }
                    }
                    process.StartInfo.Arguments = "-delstore -user MY \"30 8c e4 36 9a 39 d5 8a 45 40 f9 f8 28 e9 25 97\"";
                    process.Start();
                    process.WaitForExit();

                    int count = 0;

                    foreach (var packagePath in Packages)
                    {
                        if (!File.Exists(packagePath))
                        {
                            ++count;
                            Logging($"The package {Path.GetFileName(packagePath)} does not exist in the drive {drive}\\", LoggingOption.Error);
                            Logging($"{new System.IO.FileNotFoundException("The system cannot find the file specified.")}", LoggingOption.Exception);
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {Path.GetFileName(packagePath)}");
                            Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] The package {Path.GetFileName(packagePath)} does not exist in the drive {drive}\\");
                            Console.ResetColor();
                            continue;
                        }

                        string name = string.Empty;
                        string version = string.Empty;
                        string language = string.Empty;
                        string processorArchitecture = string.Empty;
                        string publicKeyToken = string.Empty;

                        foreach (var assembly in XElement.Load(packagePath).Elements().Where(w => w.Name.LocalName == "assemblyIdentity"))
                        {
                            foreach (var assemblyIdentity in assembly.Attributes())
                            {
                                if (assemblyIdentity.Name == "name")
                                {
                                    name = assemblyIdentity.Value;
                                }
                                else if (assemblyIdentity.Name == "version")
                                {
                                    version = assemblyIdentity.Value;
                                }
                                else if (assemblyIdentity.Name == "language")
                                {
                                    if (assemblyIdentity.Value == "neutral") language = "none";
                                    else language = assemblyIdentity.Value;
                                }
                                else if (assemblyIdentity.Name == "processorArchitecture")
                                {
                                    processorArchitecture = assemblyIdentity.Value;
                                }
                                else if (assemblyIdentity.Name == "publicKeyToken")
                                {
                                    publicKeyToken = assemblyIdentity.Value;
                                }
                            }
                        }

                        string tempPackageDirectory = Directory.CreateDirectory(Path.Combine(TempDirectory, name)).FullName;
                        File.Copy($"{packagePath}", $"{tempPackageDirectory}\\update.mum");
                        if (File.Exists($"{Path.GetDirectoryName(packagePath)}\\{Path.GetFileNameWithoutExtension(packagePath)}.cat"))
                        {
                            File.Copy($"{Path.GetDirectoryName(packagePath)}\\{Path.GetFileNameWithoutExtension(packagePath)}.cat", $"{tempPackageDirectory}\\update.cat");
                        }
                        else if (File.Exists($"{drive}\\Windows\\system32\\CATROOT\\{{F750E6C3-38EE-11D1-85E5-00C04FC295EE}}\\{name}.cat"))
                        {
                            File.Copy($"{drive}\\Windows\\system32\\CATROOT\\{{F750E6C3-38EE-11D1-85E5-00C04FC295EE}}\\{name}.cat", $"{tempPackageDirectory}\\update.cat");
                        }

                        ThrowErrorAllowed = true;

                        foreach (var package in XElement.Load(packagePath).Elements().Where(w => w.Name.LocalName == "package"))
                        {
                            foreach (var customInformation in package.Elements().Where(w => w.Name.LocalName == "customInformation"))
                            {
                                ++count;
                                Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {name}");

                                bool fileNotFoundBreak = false;
                                bool unidentifiedFileBreak = false;

                                foreach (var file in customInformation.Elements().Where(w => w.Name.LocalName == "file"))
                                {
                                    string driveFilePath = string.Empty;
                                    string cabFilePath = string.Empty;

                                    foreach (var fileAttributes in file.Attributes().Where(w => w.Name == "name" && w.Value.StartsWith("$(runtime.")))
                                    {
                                        if (fileAttributes.Value.Contains("$(runtime.bootdrive)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.bootdrive)", $"{drive}");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.programdata)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.programdata)", $"{drive}\\ProgramData");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.programfiles)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.programfiles)", $"{drive}\\PROGRAM FILES");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.commonfiles)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.commonfiles)", $"{drive}\\PROGRAM FILES\\COMMON FILES");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.startmenu)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.startmenu)", $"{drive}\\ProgramData\\Microsoft\\Windows\\Start Menu");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.systemroot)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.systemroot)", $"{drive}\\Windows");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.fonts)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.fonts)", $"{drive}\\Windows\\Fonts");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.inf)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.inf)", $"{drive}\\Windows\\Inf");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.system)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.system)", $"{drive}\\Windows\\System");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.system32)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.system32)", $"{drive}\\Windows\\System32");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.drivers)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.drivers)", $"{drive}\\Windows\\System32\\Drivers");
                                        }
                                        else if (fileAttributes.Value.Contains("$(runtime.wbem)"))
                                        {
                                            driveFilePath = fileAttributes.Value.Replace("$(runtime.wbem)", $"{drive}\\Windows\\System32\\wbem");
                                        }
                                        else
                                        {
                                            Logging($"Unidentified file {fileAttributes.Value}.", LoggingOption.Error);
                                            Logging("", LoggingOption.Exception);
                                            Console.ForegroundColor = ConsoleColor.Red;
                                            if (ThrowErrorAllowed) StandardError($"Unidentified file {fileAttributes.Value}. Please report the error or send the log to the developer.", name, count, OutputOption.Dump);
                                            else StandardError($"Unidentified file {fileAttributes.Value}. Please report the error or send the log to the developer.", name, count, OutputOption.Error);
                                            unidentifiedFileBreak = true;
                                        }
                                        break;
                                    }
                                    if (!unidentifiedFileBreak)
                                    {
                                        foreach (var fileAttributes in file.Attributes().Where(w => w.Name == "cabpath"))
                                        {
                                            cabFilePath = fileAttributes.Value;
                                            break;
                                        }

                                        if (cabFilePath.StartsWith($"{processorArchitecture}_", StringComparison.OrdinalIgnoreCase) && cabFilePath.EndsWith($".manifest", StringComparison.OrdinalIgnoreCase))
                                        {
                                            try
                                            {
                                                File.Copy($"{drive}\\Windows\\WinSxS\\Manifests\\{cabFilePath}", $"{tempPackageDirectory}\\{cabFilePath}");
                                            }
                                            catch (Exception ex)
                                            {
                                                Logging($"Failed to dump the file {drive}\\Windows\\WinSxS\\Manifests\\{cabFilePath} from the package {name}", LoggingOption.Error);
                                                Logging($"{ex}", LoggingOption.Exception);
                                                Console.ForegroundColor = ConsoleColor.Red;
                                                if (ThrowErrorAllowed) StandardError("Failed to dump the manifest file from the package.", name, count, OutputOption.Dump);
                                                else StandardError("Failed to dump the manifest file from the package.", name, count, OutputOption.Error);
                                                fileNotFoundBreak = true;
                                            }
                                        }
                                        else if (Path.GetFileNameWithoutExtension(cabFilePath) != "update")
                                        {
                                            try
                                            {
                                                Directory.CreateDirectory($"{tempPackageDirectory}\\{Path.GetDirectoryName(cabFilePath)}");
                                                File.Copy(driveFilePath, $"{tempPackageDirectory}\\{cabFilePath}");
                                            }
                                            catch (System.IO.FileNotFoundException ex)
                                            {
                                                Logging($"Couldn't find the file {driveFilePath} of package {name} from the drive {drive}\\", LoggingOption.Error);
                                                Logging($"{ex}", LoggingOption.Exception);
                                                if (ThrowErrorAllowed) StandardError($"Couldn't find the file {driveFilePath} from the package.", name, count, OutputOption.Dump);
                                                else StandardError($"Couldn't find the file {driveFilePath} from the package.", name, count, OutputOption.Error);
                                                fileNotFoundBreak = true;
                                            }
                                            catch (System.IO.DirectoryNotFoundException ex)
                                            {
                                                Logging($"Couldn't find the file {driveFilePath} of package {name} from the drive {drive}\\", LoggingOption.Error);
                                                Logging($"{ex}", LoggingOption.Exception);
                                                if (ThrowErrorAllowed) StandardError($"Couldn't find the file {driveFilePath} from the package.", name, count, OutputOption.Dump);
                                                else StandardError($"Couldn't find the file {driveFilePath} from the package.", name, count, OutputOption.Error);
                                                fileNotFoundBreak = true;
                                            }
                                            catch (Exception ex)
                                            {
                                                Logging($"Failed to dump the file {driveFilePath} from the package {name}", LoggingOption.Error);
                                                Logging($"{ex}", LoggingOption.Exception);
                                                if (ThrowErrorAllowed) StandardError($"Failed to dump the file {driveFilePath} from the package.", name, count, OutputOption.Dump);
                                                else StandardError($"Failed to dump the file {driveFilePath} from the package.", name, count, OutputOption.Error);
                                                fileNotFoundBreak = true;
                                            }
                                        }
                                    }
                                }
                                if (fileNotFoundBreak || unidentifiedFileBreak)
                                {
                                    ForceDeleteDirectory(tempPackageDirectory);
                                    break;
                                }

                                var manifests = Directory.GetFiles(tempPackageDirectory, "*.manifest", System.IO.SearchOption.TopDirectoryOnly);
                                foreach (var manifest in manifests)
                                {
                                    process.StartInfo.FileName = "sxsexp32.exe";
                                    process.StartInfo.Arguments = $"\"{manifest}\" \"{manifest}\"";
                                    process.Start();
                                    process.WaitForExit();
                                }

                                Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Packing] {name}");
                                try
                                {
                                    var allFiles = Directory.GetFiles(tempPackageDirectory, "*", System.IO.SearchOption.AllDirectories);
                                    CabArchiver archive = new CabArchiver();

                                    foreach (var allFile in allFiles)
                                        archive.AddFile(allFile.Replace(tempPackageDirectory, ""), allFile);

                                    archive.Save($"{output}\\{Path.GetFileName(tempPackageDirectory)}.cab", Microsoft.WindowsPhone.ImageUpdate.Tools.CompressionType.MSZip);
                                }
                                catch (Exception ex)
                                {
                                    Logging($"Failed to pack the file {output}\\{Path.GetFileName(tempPackageDirectory)}.cab", LoggingOption.Error);
                                    Logging($"{ex}", LoggingOption.Exception);
                                    StandardError($"Failed to pack the file {output}\\{Path.GetFileName($"{tempPackageDirectory}")}.cab", name, count, OutputOption.Pack);
                                    if (File.Exists($"{output}\\{Path.GetFileName($"{tempPackageDirectory}")}.cab"))
                                        File.Delete($"{output}\\{Path.GetFileName($"{tempPackageDirectory}")}.cab");
                                    break;
                                }

                                if (arguments.Sign)
                                {
                                    Console.WriteLine($"[{count.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Signing] {name}");

                                    process.StartInfo.FileName = "SignTool.exe";
                                    process.StartInfo.Arguments = $"sign /v /s my /i \"Windows Phone Intermediate 2013\" /n \"Windows Phone OEM Test Cert 2013 (TEST ONLY)\" /fd SHA256 \"{output}\\{name}.cab\"";
                                    process.Start();
                                    process.WaitForExit();

                                    if (process.ExitCode != 0)
                                    {
                                        Logging($"Failed to sign the package {output}\\{name}.cab", LoggingOption.Error);
                                        Logging(process.StandardError.ReadToEnd(), LoggingOption.Exception);
                                        StandardError($"Failed to sign the package {output}\\{name}.cab", name, count, OutputOption.Sign);
                                        break;
                                    }
                                }
                            }
                        }
                        ForceDeleteDirectory(tempPackageDirectory);
                    }
                }
                catch (Exception ex)
                {
                    Logging("Unhandled exception.", LoggingOption.Error);
                    Logging($"{ex}", LoggingOption.Exception);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(ex);
                    Console.ResetColor();
                }
                finally
                {
                    if (Directory.Exists($"{Path.GetTempPath()}Certificates"))
                        ForceDeleteDirectory($"{Path.GetTempPath()}Certificates");

                    var ex = ForceDeleteDirectory(TempDirectory);
                    if (ex != null)
                    {
                        Logging($"Failed to wipe the directory {TempDirectory}.", LoggingOption.Warning);
                        Logging($"{ex}", LoggingOption.Exception);
                    }
                    Logging("Exiting the CBSExtractor.", LoggingOption.Information);
                }
            })
            .WithNotParsed(err => DisplayHelp(result));
        }

        enum OutputOption
        {
            Error,
            Dump,
            Pack,
            Sign
        }

        static void StandardError(string errorText, string packageName, int currentCount, OutputOption option)
        {
            ThrowErrorAllowed = false;
            Console.ForegroundColor = ConsoleColor.Red;
            switch (option)
            {
                case OutputOption.Error:
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
                case OutputOption.Dump:
                    Console.SetCursorPosition(0, Console.CursorTop - 1);
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
                case OutputOption.Pack:
                    Console.SetCursorPosition(0, Console.CursorTop - 2);
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Packing] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
                case OutputOption.Sign:
                    Console.SetCursorPosition(0, Console.CursorTop - 3);
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Dumping] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Packing] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][Signing] {packageName}");
                    Console.WriteLine($"[{currentCount.ToString().PadLeft(Packages.Count().ToString().Length, '0')}/{Packages.Count()}][ Error ] {errorText}");
                    break;
            }
            Console.ResetColor();
        }

        static void DisplayHelp<T>(ParserResult<T> result)
        {
            var helpText = HelpText.AutoBuild(result, h =>
            {
                h.MaximumDisplayWidth = 120;
                h.Heading = $"{InternalName} {FileVersion}";
                h.Copyright = $"{LegalCopyright} - {CompanyName}";
                return HelpText.DefaultParsingErrorsHandler(result, h);
            }, e => e);
            Console.WriteLine(helpText);
        }

        public static void GetResourceFile(string resourceName)
        {
            var embeddedResource = Assembly.GetExecutingAssembly().GetManifestResourceNames().Where(s => s.Contains(resourceName)).ToArray();

            if (!string.IsNullOrWhiteSpace(embeddedResource[0]))
            {
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(embeddedResource[0]))
                {
                    var data = new byte[stream.Length];
                    stream.Read(data, 0, data.Length);
                    File.WriteAllBytes($"{Path.GetTempPath()}{resourceName}", data);
                    stream.Dispose();
                }
            }
        }

        private readonly static string[] Certificates =
        {
            "OEM_App_Test_Cert_2013.cer",
            "OEM_App_Test_Cert_2013.pfx",
            "OEM_HAL_Extension_Test_Cert_2013.cer",
            "OEM_HAL_Extension_Test_Cert_2013.pfx",
            "OEM_Intermediate_Cert.cer",
            "OEM_Intermediate_Cert.pfx",
            "OEM_Intermediate_FFU_Cert.cer",
            "OEM_Intermediate_FFU_Cert.pfx",
            "OEM_PP_Test_Cert_2013.cer",
            "OEM_PP_Test_Cert_2013.pfx",
            "OEM_PPL_Test_Cert_2013.cer",
            "OEM_PPL_Test_Cert_2013.pfx",
            "OEM_Root_CA.cer",
            "OEM_Root_CA.pfx",
            "OEM_Root_CA2.cer",
            "OEM_Test_Cert_2013.cer",
            "OEM_Test_Cert_2013.pfx",
            "OEM_Test_PK_Cert_2013.cer",
            "OEM_Test_PK_Cert_2013.pfx",
        };

        static Exception ForceDeleteDirectory(string directory)
        {
            try
            {
                string[] files = Directory.GetFiles(directory, "*", System.IO.SearchOption.AllDirectories);
                foreach (var file in files)
                {
                    File.SetAttributes(file, System.IO.FileAttributes.Normal);
                }

                Directory.Delete(directory, true);
                return null;
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        enum LoggingOption
        {
            Information,
            Warning,
            Error,
            Exception
        }

        static void Logging(object content, LoggingOption option)
        {
            string linesToAdd = string.Empty;
            switch (option)
            {
                case LoggingOption.Information:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][{option.ToString()}] {(string)content}\n";
                    break;
                case LoggingOption.Warning:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][  {option.ToString()}  ] {(string)content}\n";
                    break;
                case LoggingOption.Error:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][   {option.ToString()}   ] {(string)content}\n";
                    break;
                case LoggingOption.Exception:
                    linesToAdd = $"[{DateTime.Now:hh:mm:ss}][ {option.ToString()} ] {(string)content}\n";
                    break;
            }

            File.AppendAllText($"{CurrentDirectory}\\CBSExtractor.log", linesToAdd);
        }

        internal class Options
        {
            [Option('d', "drive", HelpText = "A path to the source drive to dump the CBS packages from.\nExamples. D:\\\n          D:\\EFIESP", Required = true)]
            public string Drive { get; set; }

            [Option('o', "output", HelpText = "A path to the output folder to save the CBS packages dump.\nExamples. C:\\Users\\User\\Desktop\\Output\n          \"C:\\Users\\User\\Desktop\\CBS Dumps\"", Required = true)]
            public string Output { get; set; }

            [Option('f', "filter", HelpText = "Optional. Dump only the given CBS packages.\nExamples. Microsoft.MainOS.Production\n          Microsoft.MainOS.Production;Microsoft.MobileCore.Prod.MainOS;...")]
            public string Filter { get; set; }

            [Option('s', "sign", HelpText = "Optional. Test sign the output CBS packages.", Default = false)]
            public bool Sign { get; set; }
        }
    }
}
