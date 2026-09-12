using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Smart7z Shell Launcher")]
[assembly: System.Reflection.AssemblyProduct("Smart 7z Ultra")]
[assembly: System.Reflection.AssemblyCompany("Smart7z")]
[assembly: System.Reflection.AssemblyDescription("Lightweight Explorer IPC launcher for Smart 7z Ultra")]

namespace Smart7zShell
{
    internal static class NativeMethods
    {
        internal const uint Synchronize = 0x00100000;
        internal const int ErrorFileNotFound = 2;
        internal const int ErrorAccessDenied = 5;
        internal const uint DriveUnknown = 0;
        internal const uint DriveNoRootDir = 1;
        internal const uint DriveRemote = 4;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr OpenMutex(uint desiredAccess, bool inheritHandle, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint GetDriveType(string rootPathName);
    }

    internal sealed class LaunchRequest
    {
        internal readonly List<string> Paths = new List<string>();
        internal bool AutoStart = true;
        internal string CleanupPolicy = "keep";
        internal bool ExtractToSource;
        internal bool ContextMenu;
    }

    [DataContract]
    internal sealed class IpcState
    {
        [DataMember(Name = "version")]
        internal int Version = 0;

        [DataMember(Name = "token")]
        internal string Token = string.Empty;

        [DataMember(Name = "port")]
        internal int Port = 0;

        [DataMember(Name = "pid")]
        internal int Pid = 0;
    }

    [DataContract]
    internal sealed class WireRequest
    {
        [DataMember(Name = "version")]
        internal int Version;

        [DataMember(Name = "token")]
        internal string Token;

        [DataMember(Name = "action")]
        internal string Action;

        [DataMember(Name = "paths")]
        internal string[] Paths;

        [DataMember(Name = "auto_start")]
        internal bool AutoStart;

        [DataMember(Name = "cleanup_policy")]
        internal string CleanupPolicy;

        [DataMember(Name = "extract_to_source")]
        internal bool ExtractToSource;

        [DataMember(Name = "context_menu")]
        internal bool ContextMenu;
    }

    [DataContract]
    internal sealed class WireResponse
    {
        [DataMember(Name = "accepted")]
        internal bool Accepted = false;

        [DataMember(Name = "reason")]
        internal string Reason = string.Empty;
    }

    internal sealed class ForwardResult
    {
        internal readonly bool Accepted;
        internal readonly string Reason;
        internal readonly bool ServerReached;

        internal ForwardResult(bool accepted, string reason, bool serverReached)
        {
            Accepted = accepted;
            Reason = reason ?? string.Empty;
            ServerReached = serverReached;
        }
    }

    internal static class Program
    {
        private const int IpcVersion = 3;
        private const int IpcMaxBytes = 256 * 1024;
        private const int IpcMaxPaths = 2000;
        private const int IpcStateMaxBytes = 4096;
        private const int IpcReplyMaxBytes = 4096;
        private const int ConnectTimeoutMilliseconds = 200;
        private const int ReplyTimeoutMilliseconds = 6000;
        private const string InstanceMutexName = "Smart7z_Instance_Mutex";
        private const string MainExecutableName = "Smart7z.exe";

        [STAThread]
        private static int Main(string[] args)
        {
            args = args ?? new string[0];
            try
            {
                ForwardResult result = Forward(ParseArguments(args));
                if (result.Accepted)
                {
                    return 0;
                }
                if (result.ServerReached &&
                    !string.Equals(result.Reason, "server_stopping", StringComparison.Ordinal))
                {
                    ShowForwardFailure(result);
                    return 1;
                }
            }
            catch (Exception)
            {
                // The full application owns diagnostics for cold-start and fallback failures.
            }
            return StartMainApplication(args);
        }

        private static LaunchRequest ParseArguments(IEnumerable<string> args)
        {
            LaunchRequest request = new LaunchRequest();
            bool parseOptions = true;
            foreach (string value in args)
            {
                if (parseOptions && value == "--")
                {
                    parseOptions = false;
                }
                else if (parseOptions && value == "--queue")
                {
                    request.AutoStart = false;
                }
                else if (parseOptions && value == "--start")
                {
                    request.AutoStart = true;
                }
                else if (parseOptions && value == "--keep-source")
                {
                    request.CleanupPolicy = "keep";
                }
                else if (parseOptions && value == "--delete-source")
                {
                    request.CleanupPolicy = "permanent";
                }
                else if (parseOptions && value == "--extract-here")
                {
                    request.ExtractToSource = true;
                }
                else if (parseOptions && value == "--context-menu")
                {
                    request.ContextMenu = true;
                }
                else
                {
                    request.Paths.Add(value);
                }
            }
            return request;
        }

        private static ForwardResult Forward(LaunchRequest request)
        {
            if (request.Paths.Count > IpcMaxPaths || (request.ContextMenu && request.Paths.Count == 0))
            {
                return new ForwardResult(false, "invalid_paths", false);
            }

            bool? mutexExists = InstanceMutexExists();
            if (mutexExists == false)
            {
                return new ForwardResult(false, "instance_unavailable", false);
            }

            IpcState state = ReadState(GetStatePath());
            if (state == null)
            {
                return new ForwardResult(false, "state_unavailable", false);
            }

            List<string> normalizedPaths = new List<string>(request.Paths.Count);
            foreach (string path in request.Paths)
            {
                string normalized = NormalizeLocalPath(path);
                if (normalized == null)
                {
                    return new ForwardResult(false, "invalid_paths", false);
                }
                normalizedPaths.Add(normalized);
            }

            WireRequest wireRequest = new WireRequest
            {
                Version = IpcVersion,
                Token = state.Token,
                Action = normalizedPaths.Count == 0 ? "activate" : "enqueue",
                Paths = normalizedPaths.ToArray(),
                AutoStart = request.AutoStart,
                CleanupPolicy = request.CleanupPolicy,
                ExtractToSource = request.ExtractToSource,
                ContextMenu = request.ContextMenu
            };
            byte[] payload = SerializeJson(wireRequest);
            if (payload.Length > IpcMaxBytes)
            {
                return new ForwardResult(false, "request_too_large", false);
            }
            return SendRequest(state.Port, payload);
        }

        private static bool? InstanceMutexExists()
        {
            IntPtr handle = NativeMethods.OpenMutex(
                NativeMethods.Synchronize,
                false,
                InstanceMutexName
            );
            if (handle != IntPtr.Zero)
            {
                NativeMethods.CloseHandle(handle);
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (error == NativeMethods.ErrorFileNotFound)
            {
                return false;
            }
            if (error == NativeMethods.ErrorAccessDenied)
            {
                return true;
            }
            return null;
        }

        private static string GetStatePath()
        {
            string stateRoot = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(stateRoot))
            {
                stateRoot = Environment.GetEnvironmentVariable("TEMP");
            }
            if (string.IsNullOrEmpty(stateRoot))
            {
                stateRoot = Environment.GetEnvironmentVariable("TMP");
            }
            if (string.IsNullOrEmpty(stateRoot))
            {
                stateRoot = Path.GetTempPath();
            }
            stateRoot = Path.Combine(Path.GetFullPath(stateRoot), "Smart7z");
            return Path.Combine(stateRoot, "ipc-v" + IpcVersion + ".json");
        }

        private static IpcState ReadState(string path)
        {
            try
            {
                byte[] raw;
                using (FileStream stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete
                ))
                {
                    if (stream.Length < 1 || stream.Length > IpcStateMaxBytes)
                    {
                        return null;
                    }
                    raw = ReadExactly(stream, checked((int)stream.Length));
                }
                if (raw == null)
                {
                    return null;
                }
                IpcState state = DeserializeJson<IpcState>(raw);
                if (state == null || state.Version != IpcVersion ||
                    string.IsNullOrEmpty(state.Token) || state.Token.Length < 32 ||
                    state.Token.Length > 256 || state.Port < 1 || state.Port > 65535 ||
                    state.Pid <= 0)
                {
                    return null;
                }
                return state;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static string NormalizeLocalPath(string path)
        {
            if (string.IsNullOrEmpty(path) || path.IndexOf('\0') >= 0)
            {
                return null;
            }
            try
            {
                string normalized = Path.GetFullPath(path);
                if (normalized.StartsWith("\\\\", StringComparison.Ordinal) ||
                    (!File.Exists(normalized) && !Directory.Exists(normalized)))
                {
                    return null;
                }
                string root = Path.GetPathRoot(normalized);
                if (string.IsNullOrEmpty(root) || root.Length < 3 || root[1] != ':')
                {
                    return null;
                }
                uint driveType = NativeMethods.GetDriveType(root);
                if (driveType == NativeMethods.DriveUnknown ||
                    driveType == NativeMethods.DriveNoRootDir ||
                    driveType == NativeMethods.DriveRemote)
                {
                    return null;
                }
                return normalized;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static ForwardResult SendRequest(int port, byte[] payload)
        {
            bool serverReached = false;
            try
            {
                using (TcpClient client = new TcpClient(AddressFamily.InterNetwork))
                {
                    IAsyncResult connect = client.BeginConnect(IPAddress.Loopback, port, null, null);
                    try
                    {
                        if (!connect.AsyncWaitHandle.WaitOne(ConnectTimeoutMilliseconds))
                        {
                            return new ForwardResult(false, "socket_timeout", false);
                        }
                        client.EndConnect(connect);
                    }
                    finally
                    {
                        connect.AsyncWaitHandle.Close();
                    }

                    serverReached = true;
                    client.SendTimeout = ReplyTimeoutMilliseconds;
                    client.ReceiveTimeout = ReplyTimeoutMilliseconds;
                    using (NetworkStream stream = client.GetStream())
                    {
                        stream.WriteTimeout = ReplyTimeoutMilliseconds;
                        stream.ReadTimeout = ReplyTimeoutMilliseconds;
                        WriteFrame(stream, payload);
                        client.Client.Shutdown(SocketShutdown.Send);

                        byte[] header = ReadExactly(stream, 4);
                        if (header == null)
                        {
                            return new ForwardResult(false, "reply_header_unavailable", true);
                        }
                        int replyLength = ReadNetworkInt32(header);
                        if (replyLength <= 0 || replyLength > IpcReplyMaxBytes)
                        {
                            return new ForwardResult(false, "invalid_reply", true);
                        }
                        byte[] reply = ReadExactly(stream, replyLength);
                        if (reply == null)
                        {
                            return new ForwardResult(false, "reply_body_unavailable", true);
                        }
                        WireResponse response = DeserializeJson<WireResponse>(reply);
                        if (response == null)
                        {
                            return new ForwardResult(false, "invalid_reply", true);
                        }
                        string reason = string.IsNullOrEmpty(response.Reason)
                            ? "not_accepted"
                            : response.Reason;
                        return new ForwardResult(response.Accepted, reason, true);
                    }
                }
            }
            catch (Exception)
            {
                return new ForwardResult(
                    false,
                    serverReached ? "connection_lost" : "connection_unavailable",
                    serverReached
                );
            }
        }

        private static void WriteFrame(Stream stream, byte[] payload)
        {
            int networkLength = IPAddress.HostToNetworkOrder(payload.Length);
            byte[] header = BitConverter.GetBytes(networkLength);
            stream.Write(header, 0, header.Length);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        }

        private static int ReadNetworkInt32(byte[] value)
        {
            return IPAddress.NetworkToHostOrder(BitConverter.ToInt32(value, 0));
        }

        private static byte[] ReadExactly(Stream stream, int count)
        {
            byte[] buffer = new byte[count];
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(buffer, offset, count - offset);
                if (read <= 0)
                {
                    return null;
                }
                offset += read;
            }
            return buffer;
        }

        private static byte[] SerializeJson<T>(T value)
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream stream = new MemoryStream())
            {
                serializer.WriteObject(stream, value);
                return stream.ToArray();
            }
        }

        private static T DeserializeJson<T>(byte[] value) where T : class
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream stream = new MemoryStream(value, false))
            {
                return serializer.ReadObject(stream) as T;
            }
        }

        private static int StartMainApplication(IEnumerable<string> args)
        {
            try
            {
                string executable = Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory,
                    MainExecutableName
                );
                if (!File.Exists(executable))
                {
                    throw new FileNotFoundException("Smart7z.exe was not found.", executable);
                }
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = JoinArguments(args),
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process process = Process.Start(startInfo))
                {
                    if (process == null)
                    {
                        throw new InvalidOperationException("Smart7z.exe did not start.");
                    }
                }
                return 0;
            }
            catch (Exception error)
            {
                MessageBox.Show(
                    "无法启动 Smart7z。\r\n\r\n" + error.Message,
                    "Smart7z 启动错误",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }
        }

        private static string JoinArguments(IEnumerable<string> args)
        {
            StringBuilder commandLine = new StringBuilder();
            foreach (string argument in args)
            {
                if (commandLine.Length > 0)
                {
                    commandLine.Append(' ');
                }
                commandLine.Append(QuoteArgument(argument ?? string.Empty));
            }
            return commandLine.ToString();
        }

        private static string QuoteArgument(string value)
        {
            if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
            {
                return value;
            }

            StringBuilder quoted = new StringBuilder(value.Length + 2);
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '"')
                {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(character);
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static void ShowForwardFailure(ForwardResult result)
        {
            MessageBox.Show(
                "已有 Smart7z 实例，但本次请求没有被确认接纳。\r\n\r\n原因：" +
                    (string.IsNullOrEmpty(result.Reason) ? "not_accepted" : result.Reason),
                "请求未接纳",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
        }
    }
}
