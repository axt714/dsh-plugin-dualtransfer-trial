# BUILD SOURCE CONTAINER ONLY. Never execute this file at runtime.
# Native and ConsoleHost here-strings compile together into one net48/x64 EXE.
# .NET Framework 4.8+, x64 Windows 11 build 22621+, local fixed NTFS only.
# No PowerShell runtime, execution-policy bypass, compiler, or DLL fallback.
# Native block is build-pinned; class 90/109 NT ABI uncertainty must refuse.
# No Windows runtime acceptance is claimed by this source container.

$nativeSource = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace DSHOwnerNative {
 public sealed class SafeFailure : Exception {
  public readonly string Code;
  public SafeFailure(string code) : base(code) { Code = code; }
 }
 public sealed class Capabilities {
  public bool nativeProcessIdentity = true;
  public bool privateFileOperations = true;
  public bool ancestorReparseChecks = true;
  public bool privateAclEvidence = true;
  public bool anchoredDirectories = true;
 }
 public sealed class ProcessIdentity {
  public bool ok = true;
  public string protocol = "dsh-owner-native-v1";
  public string platform = "win32";
  public uint pid;
  public string birth;
  public string boot;
  public string guardScope;
  public Capabilities capabilities = new Capabilities();
 }
 public sealed class ProbeResult {
  public bool ok = true;
  public string state;
  public string code;
  public ProbeResult(string stateValue, string codeValue) { state = stateValue; code = codeValue; }
 }
 public sealed class FileIdentity {
  public string dev;
  public string ino;
  public string birth;
  // Additional identities measured from this SAME handle, for Node bigint fstat.
  public string nodeDev;
  public string nodeIno;
  public string nodeBirth;
  public string nativeFileId;
 }
 public sealed class DirectoryResult {
  public bool ok = true;
  public FileIdentity identity;
  public DirectoryResult(FileIdentity value) { identity = value; }
 }
 // Root evidence has a stable THREE-field projection, not the full live/IO bridge.
 // Never serialize FileIdentity here or truncate it in any other operation.
 public sealed class PersistentDirectoryIdentity {
  public string dev;
  public string ino;
  public string birth;
  internal PersistentDirectoryIdentity(FileIdentity value) {
   dev = value.dev; ino = value.ino; birth = value.birth;
  }
 }
 public sealed class PersistentDirectoryResult {
  public bool ok = true;
  public string protocol = "dsh-owner-root-evidence-v1";
  public string platform = "win32";
  public string machineId;
  public string volumeId;
  public string boot;
  public PersistentDirectoryIdentity identity;
  public bool persistentFileIds = true;
 }
 public sealed class FileResult {
  public bool ok = true;
  public FileIdentity identity;
  public string sha256;
  public int bytes;
  public string data;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes {
   public uint Length;
   public IntPtr Descriptor;
   [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
  }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] internal struct ProcessEntry {
   public uint Size, Usage, ProcessId;
   public UIntPtr DefaultHeapId;
   public uint ModuleId, Threads, ParentProcessId;
   public int PriorityClassBase;
   public uint Flags;
   [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string ExeFile;
  }
  [StructLayout(LayoutKind.Sequential)] internal struct FT { public uint Low; public uint High; }
 [StructLayout(LayoutKind.Sequential)] internal struct BasicInfo {
  public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
  public uint Attributes;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct StandardInfo {
  public long AllocationSize, EndOfFile;
  public uint NumberOfLinks;
  public byte DeletePending, Directory;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct IdInfo {
  public ulong VolumeSerialNumber;
  [MarshalAs(UnmanagedType.ByValArray, SizeConst=16)] public byte[] FileId;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct TagInfo { public uint Attributes, ReparseTag; }
 [StructLayout(LayoutKind.Sequential)] internal struct ByHandleInfo {
  public uint Attributes;
  public FT CreationTime, LastAccessTime, LastWriteTime;
  public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct UnicodeString {
  public ushort Length, MaximumLength;
  public IntPtr Buffer;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct ObjectAttributes {
  public uint Length;
  public IntPtr RootDirectory, ObjectName;
  public uint Attributes;
  public IntPtr SecurityDescriptor, SecurityQualityOfService;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct IoStatusBlock {
  public IntPtr Status;
  public UIntPtr Information;
 }
 [StructLayout(LayoutKind.Sequential)] internal struct AclSizeInfo {
  public uint AceCount, AclBytesInUse, AclBytesFree;
 }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] internal struct VersionInfo {
  public uint Size, Major, Minor, Build, Platform;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string ServicePack;
 }
 internal static class Api {
  [DllImport("kernel32.dll", SetLastError=true)] internal static extern SafeFileHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetProcessTimes(SafeFileHandle process, out FT created, out FT exited, out FT kernel, out FT user);
  [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
  [DllImport("kernel32.dll")] internal static extern uint GetCurrentProcessId();
  [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool OpenProcessToken(SafeFileHandle process, uint access, out SafeFileHandle token);
  [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetTokenInformation(SafeFileHandle token, int informationClass, out uint value, uint length, out uint returned);
  [DllImport("kernel32.dll")] internal static extern uint GetCurrentThreadId();
   [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
   internal static extern SafeFileHandle CreateMutexExW(ref SecurityAttributes attributes, string name, uint flags, uint access);
   [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
   internal static extern bool ReleaseMutex(SafeFileHandle mutex);
   [DllImport("kernel32.dll", SetLastError=true)]
   internal static extern SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);
   [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
   internal static extern bool Process32FirstW(SafeFileHandle snapshot, ref ProcessEntry entry);
   [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
   internal static extern bool Process32NextW(SafeFileHandle snapshot, ref ProcessEntry entry);
   // PROCESS_MEMBERSHIP_INFORMATION (WDK: Win11 22H2), PHNT class109.
   [DllImport("ntdll.dll")] internal static extern int NtQueryInformationProcess(SafeFileHandle process, int informationClass, out uint information, uint length, out uint returned);
  [DllImport("ntdll.dll")] internal static extern int RtlGetVersion(ref VersionInfo version);
  [DllImport("ntdll.dll")] internal static extern int NtQuerySystemInformation(int informationClass, IntPtr buffer, uint length, out uint returned);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  internal static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("ntdll.dll")] internal static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes, out IoStatusBlock io, IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
  [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetBasic(SafeFileHandle file, int kind, out BasicInfo information, uint size);
  [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetStandard(SafeFileHandle file, int kind, out StandardInfo information, uint size);
  [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetId(SafeFileHandle file, int kind, out IdInfo information, uint size);
  [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetTag(SafeFileHandle file, int kind, out TagInfo information, uint size);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleInfo information);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetVolumeInformationByHandleW(SafeFileHandle volume, StringBuilder name, uint nameSize, out uint serial, out uint maximumComponent, out uint flags, StringBuilder fileSystem, uint fileSystemSize);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] internal static extern uint GetDriveTypeW(string root);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
  internal static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint characters, uint flags);
  [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
  internal static extern uint GetSystemFirmwareTable(uint provider, uint table, [Out] byte[] buffer, uint bytes);
  [DllImport("advapi32.dll", SetLastError=true)] internal static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetSecurityDescriptorControl(IntPtr descriptor, out ushort control, out uint revision);
  [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetAclInformation(IntPtr acl, out AclSizeInfo information, uint size, int informationClass);
  [DllImport("advapi32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);
  [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsValidSid(IntPtr sid);
  [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsValidSecurityDescriptor(IntPtr descriptor);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
  [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr memory);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool SetFilePointerEx(SafeFileHandle file, long distance, out long position, uint method);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool ReadFile(SafeFileHandle file, [Out] byte[] buffer, uint count, out uint read, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
  internal static extern bool WriteFile(SafeFileHandle file, byte[] buffer, uint count, out uint written, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool SetEndOfFile(SafeFileHandle file);
  [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool FlushFileBuffers(SafeFileHandle file);
 }
 internal sealed class KernelMutexLease : IDisposable {
   private readonly SafeFileHandle handle;
   private readonly uint threadId;
   private bool closed;
   internal KernelMutexLease(SafeFileHandle value) {
    handle = value; threadId = Api.GetCurrentThreadId();
   }
   internal void Verify() {
    if (closed || Api.GetCurrentThreadId() != threadId)
     throw new SafeFailure("OWNER_NATIVE_GUARD_UNKNOWN");
    Native.CheckKernelSecurity(handle);
   }
   public void Dispose() {
    if (closed) return;
    try {
     Verify();
     if (!Api.ReleaseMutex(handle)) throw new SafeFailure("OWNER_NATIVE_GUARD_UNKNOWN");
    } finally { closed = true; handle.Dispose(); }
   }
  }
  public sealed class AnchorLease : IDisposable {
  internal readonly List<DirectoryChain> Chains = new List<DirectoryChain>();
  private bool disposed;
  public ProcessIdentity processIdentity;
  public void Verify() {
   if (disposed) throw new SafeFailure("OWNER_NATIVE_ANCHOR_UNKNOWN");
   foreach (DirectoryChain chain in Chains) chain.Verify();
  }
  public void Dispose() {
   if (disposed) return;
   disposed = true;
   for (int i = Chains.Count - 1; i >= 0; --i) Chains[i].Dispose();
  }
 }
 internal sealed class DirectoryChain : IDisposable {
  internal readonly List<SafeFileHandle> Handles = new List<SafeFileHandle>();
  internal readonly List<FileIdentity> Identities = new List<FileIdentity>();
  internal SafeFileHandle Parent { get { return Handles[Handles.Count - 1]; } }
  public void Verify() {
   for (int i = 0; i < Handles.Count; ++i) {
    Native.CheckKind(Handles[i], true);
     Native.CheckAncestorSecurity(Handles[i], i == 0 && Handles.Count > 1);
    Native.Match(Native.Identify(Handles[i]), Identities[i]);
   }
   Native.CheckPrivate(Parent);
  }
  public void Dispose() {
   for (int i = Handles.Count - 1; i >= 0; --i) Handles[i].Dispose();
  }
 }
 public static class Native {
  private const int MaxBytes = 8 * 1024 * 1024;
  private const uint ReadControl = 0x00020000, Synchronize = 0x00100000;
  private const uint ReadAttributes = 0x80, ReadData = 1, WriteData = 2;
  private const long FileTimeEpoch = 116444736000000000L;
  private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;
  private static readonly string UserSid = WindowsIdentity.GetCurrent().User.Value;
  private static void Fail(string code) { throw new SafeFailure(code); }
  private static void Platform() {
   VersionInfo v = new VersionInfo();
   v.Size = (uint)Marshal.SizeOf(typeof(VersionInfo));
   if (IntPtr.Size != 8 || Api.RtlGetVersion(ref v) != 0 || v.Major != 10 || v.Build < 22621)
    Fail("OWNER_NATIVE_UNSUPPORTED");
   // Old kernels without the known process-membership ABI are unsupported.
   // Namespace evidence comes from host-silo Global mutexes, not sockets.
   // File-handle capability checks do not establish a loopback guard namespace.
  }
  private static string GuardScope(string boot) {
    // Supported scope is the host-silo Global kernel-object namespace. Do not
    // infer it from sockets, dates, sessions, or the reserved compartment API.
     using (SafeFileHandle self = Api.OpenProcess(0x1000 | Synchronize, false, Api.GetCurrentProcessId())) {
      if (self == null || self.IsInvalid) Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
      CheckProcessNamespace(self);
     }
     return "windows-kernel:" + boot + ":global-mutex:host-silo:0";
   }
   private static ulong Time(FT value) { return ((ulong)value.High << 32) | value.Low; }
  private static string Boot() {
   Platform();
   // Native class 90: GUID BootIdentifier; FIRMWARE_TYPE; padding; ULONGLONG
   // BootFlags. Require exactly the known 32-byte x64/arm64 layout, no fallback.
   IntPtr buffer = Marshal.AllocHGlobal(32);
   try {
    for (int i = 0; i < 32; ++i) Marshal.WriteByte(buffer, i, 0);
    uint returned;
    if (Api.NtQuerySystemInformation(90, buffer, 32, out returned) != 0 || returned != 32)
     Fail("OWNER_NATIVE_BOOT_UNKNOWN");
    byte[] bytes = new byte[16];
    Marshal.Copy(buffer, bytes, 0, bytes.Length);
    Guid guid = new Guid(bytes);
    int firmware = Marshal.ReadInt32(buffer, 16);
    if (guid == Guid.Empty || firmware < 1 || firmware > 2) Fail("OWNER_NATIVE_BOOT_UNKNOWN");
    return guid.ToString("D").ToLowerInvariant();
   } finally { Marshal.FreeHGlobal(buffer); }
  }
  private static void CheckProcessNamespace(SafeFileHandle process) {
   uint serverSiloId, membershipBytes;
    if (Api.NtQueryInformationProcess(process, 109, out serverSiloId, 4, out membershipBytes) != 0 ||
        membershipBytes != 4 || serverSiloId != 0) Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
    // An ordinary Job is not a silo namespace; the native membership proof above is authoritative.
   SafeFileHandle token;
   if (!Api.OpenProcessToken(process, 8, out token)) Fail("OWNER_NATIVE_PROCESS_UNKNOWN");
   using (token) {
    uint appContainer, returned;
    if (!Api.GetTokenInformation(token, 29, out appContainer, 4, out returned) ||
        returned != 4 || appContainer != 0) Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
   }
  }
  public static ProcessIdentity Identity(uint pid) {
   if (pid == 0 || pid > 0x7fffffff) Fail("OWNER_NATIVE_INPUT");
   string boot = Boot();
   using (SafeFileHandle process = Api.OpenProcess(0x1000 | Synchronize, false, pid)) {
    if (process == null || process.IsInvalid) Fail("OWNER_NATIVE_PROCESS_UNKNOWN");
    CheckProcessNamespace(process);
    FT created, exited, kernel, user;
    if (!Api.GetProcessTimes(process, out created, out exited, out kernel, out user) ||
        Time(created) == 0 || Api.WaitForSingleObject(process, 0) != 258)
     Fail("OWNER_NATIVE_PROCESS_UNKNOWN");
    ProcessIdentity value = new ProcessIdentity();
    value.pid = pid; value.birth = Time(created).ToString(Invariant); value.boot = boot;
    value.guardScope = GuardScope(boot);
    return value;
   }
  }
  public static ProbeResult Probe(uint pid, string birth, string boot) {
   if (pid == 0 || pid > 0x7fffffff || !Regex.IsMatch(birth ?? "", @"^\d{1,24}$") ||
       !Regex.IsMatch(boot ?? "", @"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"))
    Fail("OWNER_NATIVE_INPUT");
   if (Boot() != boot) Fail("OWNER_NATIVE_BOOT_MISMATCH");
    GuardScope(boot); // Unknown namespace must never be converted to death evidence.
   using (SafeFileHandle process = Api.OpenProcess(0x1000 | Synchronize, false, pid)) {
    int error = Marshal.GetLastWin32Error();
    if (process == null || process.IsInvalid) {
     if (error == 87) return new ProbeResult("dead", "OWNER_PROCESS_ABSENT");
     Fail("OWNER_NATIVE_PROCESS_UNKNOWN");
    }
    CheckProcessNamespace(process);
    FT created, exited, kernel, user;
    if (!Api.GetProcessTimes(process, out created, out exited, out kernel, out user) || Time(created) == 0)
     Fail("OWNER_NATIVE_PROCESS_UNKNOWN");
    if (Time(created).ToString(Invariant) != birth)
     return new ProbeResult("reused", "OWNER_PROCESS_REUSED");
    uint wait = Api.WaitForSingleObject(process, 0);
    if (wait == 0) return new ProbeResult("dead", "OWNER_PROCESS_ABSENT");
    if (wait == 258) return new ProbeResult("active", "OWNER_PROCESS_ACTIVE");
    Fail("OWNER_NATIVE_PROCESS_UNKNOWN"); return null;
   }
  }
  internal static void CheckKernelSecurity(SafeFileHandle handle) {
    IntPtr owner, group, dacl, sacl, descriptor;
    // SE_KERNEL_OBJECT=6. The descriptor supplied to CreateMutexEx is NOT proof
    // when the named object already exists: inspect this actual returned handle.
    if (Api.GetSecurityInfo(handle, 6, 1 | 4, out owner, out group, out dacl, out sacl, out descriptor) != 0)
     Fail("OWNER_NATIVE_GUARD_UNKNOWN");
    try {
     ushort control; uint revision; AclSizeInfo size = new AclSizeInfo();
     if (descriptor == IntPtr.Zero || !Api.IsValidSecurityDescriptor(descriptor) ||
         !Api.GetSecurityDescriptorControl(descriptor, out control, out revision) ||
         (control & (4 | 0x1000)) != (4 | 0x1000) || owner == IntPtr.Zero ||
         !Api.IsValidSid(owner) || new SecurityIdentifier(owner).Value != UserSid ||
         dacl == IntPtr.Zero || !Api.GetAclInformation(dacl, out size, (uint)Marshal.SizeOf(typeof(AclSizeInfo)), 2) ||
         size.AceCount < 1 || size.AceCount > 16 || size.AclBytesInUse > 4096)
      Fail("OWNER_NATIVE_GUARD_UNKNOWN");
     bool userAllowed = false, systemAllowed = false;
     for (uint i = 0; i < size.AceCount; ++i) {
      IntPtr ace;
      if (!Api.GetAce(dacl, i, out ace)) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
      ushort bytes = unchecked((ushort)Marshal.ReadInt16(ace, 2));
      if (Marshal.ReadByte(ace, 0) != 0 || Marshal.ReadByte(ace, 1) != 0 || bytes < 16 ||
          unchecked((uint)Marshal.ReadInt32(ace, 4)) != 0x001F0001U)
       Fail("OWNER_NATIVE_GUARD_UNKNOWN");
      IntPtr sid = IntPtr.Add(ace, 8);
      if (!Api.IsValidSid(sid)) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
      SecurityIdentifier identifier = new SecurityIdentifier(sid);
      if (identifier.BinaryLength + 8 > bytes) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
      string value = identifier.Value;
      if (value != UserSid && value != "S-1-5-18") Fail("OWNER_NATIVE_GUARD_UNKNOWN");
      if (value == UserSid) userAllowed = true;
      if (value == "S-1-5-18") systemAllowed = true;
     }
     if (!userAllowed || !systemAllowed) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
    } finally { if (descriptor != IntPtr.Zero) Api.LocalFree(descriptor); }
   }
   private static KernelMutexLease AcquireKernel(string key) {
    if (!Regex.IsMatch(key ?? "", @"^[0-9a-f]{64}$")) Fail("OWNER_NATIVE_INPUT");
    GuardScope(Boot());
    IntPtr security = IntPtr.Zero; SafeFileHandle handle = null; bool acquired = false;
    try {
     string sddl = "O:" + UserSid + "D:P(A;;0x001F0001;;;" + UserSid + ")(A;;0x001F0001;;;SY)";
     uint bytes;
     if (!Api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out security, out bytes))
      Fail("OWNER_NATIVE_GUARD_UNKNOWN");
     SecurityAttributes attributes = new SecurityAttributes();
     attributes.Length = (uint)Marshal.SizeOf(typeof(SecurityAttributes));
     attributes.Descriptor = security; attributes.Inherit = false;
     handle = Api.CreateMutexExW(ref attributes, @"Global\DSH-DualTransfer-C65-" + key, 0,
       ReadControl | Synchronize | 1U);
     if (handle == null || handle.IsInvalid) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
     CheckKernelSecurity(handle);
     uint wait = Api.WaitForSingleObject(handle, 0);
     if (wait == 258) Fail("OWNER_NATIVE_GUARD_BUSY");
     // Abandonment grants ownership only. It is NEVER evidence that an old
     // business owner is dead; the engine must prove that independently.
     if (wait != 0 && wait != 0x80) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
     acquired = true; CheckKernelSecurity(handle);
     KernelMutexLease lease = new KernelMutexLease(handle);
     handle = null; return lease;
    } finally {
     if (handle != null) {
      if (acquired) Api.ReleaseMutex(handle);
      handle.Dispose();
     }
     if (security != IntPtr.Zero) Api.LocalFree(security);
    }
   }
   public static void ServeKernelGuard(string key) {
    bool ready = false;
    try {
     // Keep acquire/read-EOF/release in ONE native invocation on ONE OS thread.
     using (KernelMutexLease lease = AcquireKernel(key)) {
      ProcessIdentity self = Identity(Api.GetCurrentProcessId());
      lease.Verify();
      // All interpolated values below are native numeric/UUID/fixed strings,
      // not input data or paths; no PowerShell cmdlet receives this JSON.
      Console.Out.WriteLine("{\"ok\":true,\"ready\":true,\"processIdentity\":{" +
       "\"protocol\":\"dsh-owner-native-v1\",\"platform\":\"win32\",\"pid\":" + self.pid.ToString(Invariant) +
       ",\"birth\":\"" + self.birth + "\",\"boot\":\"" + self.boot + "\",\"guardScope\":\"" + self.guardScope +
       "\",\"capabilities\":{\"nativeProcessIdentity\":true,\"privateFileOperations\":true," +
       "\"ancestorReparseChecks\":true,\"privateAclEvidence\":true,\"anchoredDirectories\":true}}}");
      Console.Out.Flush(); ready = true;
      if (Console.In.Read() >= 0) Fail("OWNER_NATIVE_GUARD_UNKNOWN");
      lease.Verify();
     }
    } catch {
     // An already-ready keeper must never turn an uncertain release into exit0.
     if (ready) Environment.Exit(1);
     throw;
    }
   }
   private static uint ActualParentPid() {
    using (SafeFileHandle snapshot = Api.CreateToolhelp32Snapshot(2, 0)) {
     if (snapshot == null || snapshot.IsInvalid) Fail("OWNER_NATIVE_PARENT_UNKNOWN");
     ProcessEntry entry = new ProcessEntry(); entry.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry));
     if (!Api.Process32FirstW(snapshot, ref entry)) Fail("OWNER_NATIVE_PARENT_UNKNOWN");
     uint self = Api.GetCurrentProcessId();
     for (int count = 0; count < 65536; ++count) {
      if (entry.ProcessId == self) {
       if (entry.ParentProcessId == 0 || entry.ParentProcessId > 0x7fffffff)
        Fail("OWNER_NATIVE_PARENT_UNKNOWN");
       return entry.ParentProcessId;
      }
      entry.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry));
      if (!Api.Process32NextW(snapshot, ref entry)) Fail("OWNER_NATIVE_PARENT_UNKNOWN");
     }
     Fail("OWNER_NATIVE_PARENT_UNKNOWN"); return 0;
    }
   }
   private static SafeFileHandle ActiveActualParent(ProcessIdentity expected) {
    if (expected == null || expected.protocol != "dsh-owner-native-v1" || expected.platform != "win32" ||
        expected.pid == 0 || expected.pid > 0x7fffffff ||
        !Regex.IsMatch(expected.birth ?? "", @"^\d{1,24}$") || ActualParentPid() != expected.pid)
     Fail("OWNER_NATIVE_PARENT_UNKNOWN");
    string boot = Boot();
    if (expected.boot != boot || expected.guardScope != GuardScope(boot)) Fail("OWNER_NATIVE_PARENT_UNKNOWN");
    SafeFileHandle process = Api.OpenProcess(0x1000 | Synchronize, false, expected.pid);
    try {
     if (process == null || process.IsInvalid) Fail("OWNER_NATIVE_PARENT_UNKNOWN");
     CheckProcessNamespace(process);
     FT created, exited, kernel, user;
     if (!Api.GetProcessTimes(process, out created, out exited, out kernel, out user) ||
         Time(created) == 0 || Time(created).ToString(Invariant) != expected.birth ||
         Api.WaitForSingleObject(process, 0) != 258) Fail("OWNER_NATIVE_PARENT_UNKNOWN");
     SafeFileHandle result = process; process = null; return result;
    } finally { if (process != null) process.Dispose(); }
   }
   public static object GuardedFileOperation(string parent, FileIdentity expectedParent, string name, string action,
       FileIdentity expected, string expectedHash, string data, int payloadLength, string ioGuardKey, ProcessIdentity ownerProcess) {
    if (action == "inspect")
     return FileOperation(parent, expectedParent, name, action, expected, expectedHash, data, payloadLength);
    if (action != "create" && action != "replace" && action != "append" && action != "mkdir") Fail("OWNER_NATIVE_INPUT");
    // The parent's birth is checked AFTER taking IO and BEFORE opening any
    // target/ancestor. Hold IO through read/full hash/write/flush/readback/close.
    using (KernelMutexLease io = AcquireKernel(ioGuardKey)) {
     using (SafeFileHandle parentProcess = ActiveActualParent(ownerProcess)) {
      io.Verify();
      return FileOperation(parent, expectedParent, name, action, expected, expectedHash, data, payloadLength);
     }
    }
   }
   internal static void Match(FileIdentity actual, FileIdentity expected) {
   if (expected == null || !Regex.IsMatch(expected.dev ?? "", @"^\d{1,24}$") ||
       !Regex.IsMatch(expected.ino ?? "", @"^[0-9a-f]{32}$") ||
       !Regex.IsMatch(expected.birth ?? "", @"^\d{1,24}$")) Fail("OWNER_NATIVE_INPUT");
   if (actual.dev != expected.dev || actual.ino != expected.ino || actual.birth != expected.birth)
    Fail("OWNER_NATIVE_IDENTITY_MISMATCH");
  }
  internal static void CheckKind(SafeFileHandle handle, bool directory) {
   TagInfo tag = new TagInfo(); StandardInfo standard = new StandardInfo();
   if (!Api.GetTag(handle, 9, out tag, (uint)Marshal.SizeOf(typeof(TagInfo))) ||
       !Api.GetStandard(handle, 1, out standard, (uint)Marshal.SizeOf(typeof(StandardInfo))))
    Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
   // Refuse reparse, offline/recall, device objects and delete-pending files.
   if ((tag.Attributes & (0x400U | 0x1000U | 0x40U | 0x40000U | 0x400000U)) != 0 ||
       tag.ReparseTag != 0 || standard.DeletePending != 0 ||
       ((tag.Attributes & 0x10) != 0) != directory || (standard.Directory != 0) != directory ||
       (!directory && standard.NumberOfLinks != 1)) Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
  }
  internal static FileIdentity Identify(SafeFileHandle handle) {
   IdInfo id = new IdInfo(); BasicInfo basic = new BasicInfo(); ByHandleInfo legacy = new ByHandleInfo();
   if (!Api.GetId(handle, 18, out id, (uint)Marshal.SizeOf(typeof(IdInfo))) ||
       !Api.GetBasic(handle, 0, out basic, (uint)Marshal.SizeOf(typeof(BasicInfo))) ||
       !Api.GetFileInformationByHandle(handle, out legacy) || id.FileId == null || id.FileId.Length != 16 ||
       basic.CreationTime <= FileTimeEpoch || Time(legacy.CreationTime) != (ulong)basic.CreationTime)
    Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
   string fileId = BitConverter.ToString(id.FileId).Replace("-", "").ToLowerInvariant();
   if (fileId == "00000000000000000000000000000000") Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
   long unixNs;
   try { unixNs = checked((basic.CreationTime - FileTimeEpoch) * 100L); }
   catch { Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN"); return null; }
   FileIdentity value = new FileIdentity();
   value.dev = id.VolumeSerialNumber.ToString(Invariant); value.ino = fileId;
   value.birth = basic.CreationTime.ToString(Invariant); value.nativeFileId = fileId;
   value.nodeDev = legacy.VolumeSerialNumber.ToString(Invariant);
   value.nodeIno = (((ulong)legacy.FileIndexHigh << 32) | legacy.FileIndexLow).ToString(Invariant);
   value.nodeBirth = unixNs.ToString(Invariant);
   return value;
  }
  internal static void CheckPrivate(SafeFileHandle handle) { CheckAcl(handle, true); }
  internal static void CheckAncestorSecurity(SafeFileHandle handle, bool volumeRootAncestor) { CheckAcl(handle, false, volumeRootAncestor); }
  private static bool TrustedSid(string sid, bool volumeRootAncestor = false) {
   return sid == UserSid || sid == "S-1-5-18" || sid == "S-1-5-32-544" ||
     (volumeRootAncestor && sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
  }
  private static void CheckAcl(SafeFileHandle handle, bool requirePrivate, bool volumeRootAncestor = false) {
   IntPtr owner, group, dacl, sacl, descriptor;
   uint status = Api.GetSecurityInfo(handle, 1, 1 | 4, out owner, out group, out dacl, out sacl, out descriptor);
   if (status != 0) Fail("OWNER_NATIVE_ACL_UNKNOWN");
   try {
    ushort control; uint revision; AclSizeInfo size = new AclSizeInfo();
    if (descriptor == IntPtr.Zero || !Api.IsValidSecurityDescriptor(descriptor) ||
        !Api.GetSecurityDescriptorControl(descriptor, out control, out revision) || (control & 4) == 0 ||
        owner == IntPtr.Zero || !Api.IsValidSid(owner) ||
        (requirePrivate ? new SecurityIdentifier(owner).Value != UserSid : !TrustedSid(new SecurityIdentifier(owner).Value, volumeRootAncestor)) ||
        dacl == IntPtr.Zero || !Api.GetAclInformation(dacl, out size, (uint)Marshal.SizeOf(typeof(AclSizeInfo)), 2) ||
        size.AceCount < 1 || size.AceCount > 1024 || size.AclBytesInUse > 65535)
     Fail("OWNER_NATIVE_ACL_UNKNOWN");
    bool userAllowed = false;
    for (uint i = 0; i < size.AceCount; ++i) {
     IntPtr ace;
     if (!Api.GetAce(dacl, i, out ace)) Fail("OWNER_NATIVE_ACL_UNKNOWN");
     byte kind = Marshal.ReadByte(ace, 0), flags = Marshal.ReadByte(ace, 1);
     ushort aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
     if ((kind != 0 && kind != 1) || aceSize < 12) Fail("OWNER_NATIVE_ACL_UNKNOWN");
     IntPtr sid = IntPtr.Add(ace, 8);
     if (!Api.IsValidSid(sid)) Fail("OWNER_NATIVE_ACL_UNKNOWN");
     string value = new SecurityIdentifier(sid).Value;
     // Deny and inherit-only ACEs grant no effective access to this object.
     if (kind == 1 || (flags & 8) != 0) continue;
     uint mask = unchecked((uint)Marshal.ReadInt32(ace, 4));
     // Existing inherited private ACLs are accepted, but no untrusted ancestor
     // owner/WRITE_DAC/WRITE_OWNER can propagate an ACL change into the target.
     if (mask != 0 && !TrustedSid(value, !requirePrivate && volumeRootAncestor) &&
         (requirePrivate || (mask & (0x000C0000U | 0x10000000U)) != 0))
      Fail("OWNER_NATIVE_ACL_UNKNOWN");
     if (value == UserSid && mask != 0) userAllowed = true;
    }
    if (requirePrivate && !userAllowed) Fail("OWNER_NATIVE_ACL_UNKNOWN");
   } finally { if (descriptor != IntPtr.Zero) Api.LocalFree(descriptor); }
  }
  private static void Name(string name) {
   if (String.IsNullOrEmpty(name) || name.Length > 240 || name == "." || name == ".." ||
       name.EndsWith(".", StringComparison.Ordinal) || name.EndsWith(" ", StringComparison.Ordinal) ||
       Regex.IsMatch(name, "[\\\\/:*?\"<>|\\x00-\\x1f]") ||
       Regex.IsMatch(name, @"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
    Fail("OWNER_NATIVE_INPUT");
  }
  private static SafeFileHandle Relative(SafeFileHandle parent, string name, bool directory, bool create, bool write) {
   Name(name);
   IntPtr text = IntPtr.Zero, unicode = IntPtr.Zero, security = IntPtr.Zero;
   try {
    text = Marshal.StringToHGlobalUni(name);
    UnicodeString us = new UnicodeString(); us.Length = checked((ushort)(name.Length * 2));
    us.MaximumLength = checked((ushort)(us.Length + 2)); us.Buffer = text;
    unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
    Marshal.StructureToPtr(us, unicode, false);
    if (create) {
     string inheritance = directory ? "OICI" : "";
     string sddl = "O:" + UserSid + "D:P(A;" + inheritance + ";FA;;;" + UserSid + ")(A;" + inheritance + ";FA;;;SY)";
     uint bytes;
     if (!Api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out security, out bytes))
      Fail("OWNER_NATIVE_ACL_UNKNOWN");
    }
    ObjectAttributes attributes = new ObjectAttributes();
    attributes.Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes));
    attributes.RootDirectory = parent.DangerousGetHandle(); attributes.ObjectName = unicode;
    attributes.Attributes = 0x40 | 0x1000; // CASE_INSENSITIVE | DONT_REPARSE
    attributes.SecurityDescriptor = security;
    uint access = ReadControl | Synchronize | ReadAttributes | (directory ? 0x20U : ReadData);
    if (write && !directory) access |= WriteData;
    uint options = 0x00200000 | 0x20 | (directory ? 1U : 0x40U); // no-follow, synchronous, exact kind
    if (write || create) options |= 2; // FILE_WRITE_THROUGH
    SafeFileHandle handle; IoStatusBlock io;
    int status = Api.NtCreateFile(out handle, access, ref attributes, out io, IntPtr.Zero, 0x80,
      directory ? 3U : 1U, create ? 2U : 1U, options, IntPtr.Zero, 0);
    // NO FILE_SHARE_DELETE anywhere, and no FILE_SHARE_WRITE on leaves.
    if (status != 0 || handle == null || handle.IsInvalid) {
     if (handle != null) handle.Dispose();
     Fail("OWNER_NATIVE_IO_UNKNOWN");
    }
    if (io.Information.ToUInt64() != (create ? 2UL : 1UL)) {
     handle.Dispose(); Fail(create ? "OWNER_NATIVE_IO_UNCERTAIN" : "OWNER_NATIVE_IO_UNKNOWN");
    }
    return handle;
   } finally {
    if (security != IntPtr.Zero) Api.LocalFree(security);
    if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
    if (text != IntPtr.Zero) Marshal.FreeHGlobal(text);
   }
  }
  private static DirectoryChain OpenChain(string directory) {
   Platform();
   if (String.IsNullOrEmpty(directory) || directory.Length > 24000 || !Regex.IsMatch(directory, @"^[A-Za-z]:\\") ||
       directory.IndexOf('/') >= 0 || directory.IndexOf('\0') >= 0) Fail("OWNER_NATIVE_INPUT");
   string root = Char.ToUpperInvariant(directory[0]).ToString() + ":\\";
   if (Api.GetDriveTypeW(root) != 3) Fail("OWNER_NATIVE_UNSUPPORTED");
   string remaining = directory.Substring(3);
   if (remaining.EndsWith("\\", StringComparison.Ordinal)) remaining = remaining.Substring(0, remaining.Length - 1);
   string[] names = remaining.Length == 0 ? new string[0] : remaining.Split('\\');
   if (names.Length > 128) Fail("OWNER_NATIVE_LIMIT");
   foreach (string name in names) Name(name);
   DirectoryChain chain = new DirectoryChain();
   try {
    SafeFileHandle handle = Api.CreateFileW("\\\\?\\" + root, ReadControl | Synchronize | ReadAttributes | 0x20U,
      3, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
    if (handle == null || handle.IsInvalid) {
     if (handle != null) handle.Dispose(); Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
    }
    chain.Handles.Add(handle); CheckKind(handle, true);
    uint serial, maximumComponent, flags;
    StringBuilder volume = new StringBuilder(512), fs = new StringBuilder(64);
    if (!Api.GetVolumeInformationByHandleW(handle, volume, (uint)volume.Capacity, out serial,
        out maximumComponent, out flags, fs, (uint)fs.Capacity) || fs.ToString() != "NTFS" || (flags & 8) == 0)
     Fail("OWNER_NATIVE_UNSUPPORTED");
    chain.Identities.Add(Identify(handle));
    foreach (string name in names) {
     handle = Relative(chain.Parent, name, true, false, false);
     chain.Handles.Add(handle); CheckKind(handle, true);
     FileIdentity identity = Identify(handle);
     if (identity.dev != chain.Identities[0].dev) Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
     chain.Identities.Add(identity);
    }
    chain.Verify(); return chain;
   } catch { chain.Dispose(); throw; }
  }
  public static DirectoryResult Directory(string directory) {
   using (DirectoryChain chain = OpenChain(directory)) {
    chain.Verify(); return new DirectoryResult(Identify(chain.Parent));
   }
  }
  private static string MachineUuid() {
   // GetSystemFirmwareTable('RSMB', 0) returns RawSMBIOSData: four BYTEs,
   // little-endian DWORD Length, then bounded SMBIOS structures/string-sets.
   // SMBIOS >= 2.6 defines the UUID's first 4/2/2 bytes as little-endian;
   // Guid(byte[]) has exactly that layout. No registry/WMI/generated fallback.
   const uint provider = 0x52534D42, limit = 4 * 1024 * 1024;
   uint size = Api.GetSystemFirmwareTable(provider, 0, null, 0);
   if (size < 14 || size > limit) Fail("OWNER_NATIVE_UNSUPPORTED");
   byte[] raw = new byte[(int)size];
   if (Api.GetSystemFirmwareTable(provider, 0, raw, size) != size ||
       raw[1] < 2 || (raw[1] == 2 && raw[2] < 6)) Fail("OWNER_NATIVE_UNSUPPORTED");
   uint length = (uint)raw[4] | ((uint)raw[5] << 8) | ((uint)raw[6] << 16) | ((uint)raw[7] << 24);
   if (length != size - 8) Fail("OWNER_NATIVE_UNSUPPORTED");
   int offset = 8, structures = 0, typeOne = 0;
   bool ended = false;
   string machine = null;
   while (offset < raw.Length) {
    if (++structures > 65536 || raw.Length - offset < 6) Fail("OWNER_NATIVE_UNSUPPORTED");
    int type = raw[offset], formatted = raw[offset + 1];
    if (formatted < 4 || formatted > raw.Length - offset - 2) Fail("OWNER_NATIVE_UNSUPPORTED");
    int stringsStart = offset + formatted, end = stringsStart;
    while (end + 1 < raw.Length && (raw[end] != 0 || raw[end + 1] != 0)) ++end;
    if (end + 1 >= raw.Length || (end > stringsStart && raw[stringsStart] == 0))
     Fail("OWNER_NATIVE_UNSUPPORTED");
    int strings = end == stringsStart ? 0 : 1;
    for (int i = stringsStart; i < end; ++i) if (raw[i] == 0) ++strings;
    if (type == 1) {
     // Version 2.4+ Type 1 includes UUID, wake-up, SKU and family (27 bytes).
     if (++typeOne != 1 || formatted < 27) Fail("OWNER_NATIVE_UNSUPPORTED");
     foreach (int field in new int[] { 4, 5, 6, 7, 25, 26 })
      if (raw[offset + field] > strings) Fail("OWNER_NATIVE_UNSUPPORTED");
     byte[] uuid = new byte[16];
     Buffer.BlockCopy(raw, offset + 8, uuid, 0, uuid.Length);
     bool zero = true, ff = true;
     foreach (byte value in uuid) { zero &= value == 0; ff &= value == 255; }
     if (zero || ff) Fail("OWNER_NATIVE_UNSUPPORTED");
     machine = new Guid(uuid).ToString("D").ToLowerInvariant();
    }
    offset = end + 2;
    if (type == 127) {
     // End-of-table is the last structure, with no formatted payload or strings.
     if (formatted != 4 || strings != 0 || offset != raw.Length) Fail("OWNER_NATIVE_UNSUPPORTED");
     ended = true; break;
    }
   }
   if (!ended || typeOne != 1 || machine == null) Fail("OWNER_NATIVE_UNSUPPORTED");
   return machine;
  }
  private static string PersistentVolumeUuid(SafeFileHandle heldRoot) {
   // Query ONLY OpenChain's already-held volume-root FD, never reopen a drive
   // letter or use a caller-supplied GUID. Fixed/NTFS/same-volume remains OpenChain's job.
   uint serial, maximumComponent, flags;
   StringBuilder volume = new StringBuilder(261), fs = new StringBuilder(64);
   if (!Api.GetVolumeInformationByHandleW(heldRoot, volume, (uint)volume.Capacity, out serial,
       out maximumComponent, out flags, fs, (uint)fs.Capacity) || fs.ToString() != "NTFS" ||
       (flags & 0x01000008U) != 0x01000008U) Fail("OWNER_NATIVE_UNSUPPORTED");
   StringBuilder path = new StringBuilder(64);
   uint count = Api.GetFinalPathNameByHandleW(heldRoot, path, (uint)path.Capacity, 1);
   string final = path.ToString(), prefix = "\\\\?\\Volume{";
   Guid uuid = Guid.Empty;
   if (count == 0 || count >= path.Capacity || count != final.Length ||
       final.Length != prefix.Length + 38 || !final.StartsWith(prefix, StringComparison.Ordinal) ||
       !final.EndsWith("}\\", StringComparison.Ordinal) ||
       !Guid.TryParseExact(final.Substring(prefix.Length, 36), "D", out uuid) || uuid == Guid.Empty)
    Fail("OWNER_NATIVE_UNSUPPORTED");
   return uuid.ToString("D").ToLowerInvariant();
  }
  public static PersistentDirectoryResult PersistentDirectory(string directory) {
   // Read-only independent reboot evidence. It is not a process-death decision,
   // cleanup permission, or protection against firmware/VM clones or volume rollback.
   string boot = Boot();
   GuardScope(boot); // Current host-silo:0, non-AppContainer; no weaker fallback.
   using (DirectoryChain chain = OpenChain(directory)) {
    chain.Verify();
    string volume = PersistentVolumeUuid(chain.Handles[0]), machine = MachineUuid();
    FileIdentity full = Identify(chain.Parent);
    Match(full, chain.Identities[chain.Identities.Count - 1]);
    if (PersistentVolumeUuid(chain.Handles[0]) != volume || MachineUuid() != machine)
     Fail("OWNER_NATIVE_UNSUPPORTED");
    if (Boot() != boot) Fail("OWNER_NATIVE_BOOT_UNKNOWN");
    GuardScope(boot);
    chain.Verify();
    return new PersistentDirectoryResult { machineId = machine, volumeId = volume, boot = boot,
     identity = new PersistentDirectoryIdentity(full) };
   }
  }
  public static AnchorLease Hold(string[] paths, FileIdentity[] expected) {
   if (paths == null || expected == null || paths.Length != expected.Length || paths.Length < 1 || paths.Length > 128)
    Fail("OWNER_NATIVE_INPUT");
   AnchorLease lease = new AnchorLease();
   try {
    for (int i = 0; i < paths.Length; ++i) {
     DirectoryChain chain = OpenChain(paths[i]);
     lease.Chains.Add(chain); Match(Identify(chain.Parent), expected[i]);
    }
    lease.Verify(); lease.processIdentity = Identity(Api.GetCurrentProcessId()); return lease;
   } catch { lease.Dispose(); throw; }
  }
  private static void Seek(SafeFileHandle handle, long position) {
   long actual;
   if (!Api.SetFilePointerEx(handle, position, out actual, 0) || actual != position) Fail("OWNER_NATIVE_IO_UNKNOWN");
  }
  private static byte[] ReadAll(SafeFileHandle handle) {
   StandardInfo standard;
   if (!Api.GetStandard(handle, 1, out standard, (uint)Marshal.SizeOf(typeof(StandardInfo))) ||
       standard.EndOfFile < 0 || standard.EndOfFile > MaxBytes) Fail("OWNER_NATIVE_LIMIT");
   Seek(handle, 0);
   byte[] result = new byte[(int)standard.EndOfFile];
   int offset = 0;
   while (offset < result.Length) {
    byte[] part = new byte[Math.Min(65536, result.Length - offset)]; uint read;
    if (!Api.ReadFile(handle, part, (uint)part.Length, out read, IntPtr.Zero) || read == 0 || read > part.Length)
     Fail("OWNER_NATIVE_IO_UNKNOWN");
    Buffer.BlockCopy(part, 0, result, offset, (int)read); offset += (int)read;
   }
   byte[] extra = new byte[1]; uint trailing;
   if (!Api.ReadFile(handle, extra, 1, out trailing, IntPtr.Zero) || trailing != 0)
    Fail("OWNER_NATIVE_IO_UNKNOWN");
   StandardInfo after;
   if (!Api.GetStandard(handle, 1, out after, (uint)Marshal.SizeOf(typeof(StandardInfo))) || after.EndOfFile != result.Length)
    Fail("OWNER_NATIVE_IO_UNKNOWN");
   return result;
  }
  private static string Hash(byte[] data) {
   using (SHA256 hash = SHA256.Create()) {
    return BitConverter.ToString(hash.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
   }
  }
  private static void WriteAll(SafeFileHandle handle, byte[] data) {
   int offset = 0;
   while (offset < data.Length) {
    int length = Math.Min(65536, data.Length - offset); byte[] part = new byte[length]; uint written;
    Buffer.BlockCopy(data, offset, part, 0, length);
    if (!Api.WriteFile(handle, part, (uint)length, out written, IntPtr.Zero) || written == 0 || written > length)
     Fail("OWNER_NATIVE_IO_UNCERTAIN");
    offset += (int)written;
   }
  }
  private static bool Equal(byte[] left, byte[] right) {
   if (left.Length != right.Length) return false;
   int difference = 0;
   for (int i = 0; i < left.Length; ++i) difference |= left[i] ^ right[i];
   return difference == 0;
  }
  private static object FileOperation(string parent, FileIdentity expectedParent, string name, string action,
      FileIdentity expected, string expectedHash, string data, int payloadLength) {
   Name(name);
   bool create = action == "create" || action == "mkdir";
   bool directory = action == "mkdir";
   bool write = action == "create" || action == "replace" || action == "append";
   if (!create && action != "inspect" && action != "replace" && action != "append") Fail("OWNER_NATIVE_INPUT");
   if (create && (expected != null || expectedHash != null)) Fail("OWNER_NATIVE_INPUT");
   if ((action == "replace" || action == "append") &&
       (expected == null || !Regex.IsMatch(expectedHash ?? "", @"^[0-9a-f]{64}$"))) Fail("OWNER_NATIVE_INPUT");
   if (expectedHash != null && !Regex.IsMatch(expectedHash, @"^[0-9a-f]{64}$")) Fail("OWNER_NATIVE_INPUT");
   byte[] payload = null;
   if (write) {
    if (data == null || data.Length > ((MaxBytes + 2) / 3) * 4) Fail("OWNER_NATIVE_LIMIT");
    try { payload = Convert.FromBase64String(data); } catch { Fail("OWNER_NATIVE_INPUT"); }
    if (payload.Length > MaxBytes || payloadLength != payload.Length || Convert.ToBase64String(payload) != data)
     Fail("OWNER_NATIVE_INPUT");
   } else if (data != null || payloadLength != -1) Fail("OWNER_NATIVE_INPUT");
   bool changed = false;
   try {
    using (DirectoryChain chain = OpenChain(parent)) {
     Match(Identify(chain.Parent), expectedParent); chain.Verify();
     using (SafeFileHandle file = Relative(chain.Parent, name, directory, create, write)) {
      changed = create; // A successful FILE_CREATE is already an externally visible effect.
      CheckKind(file, directory); CheckPrivate(file);
      FileIdentity identity = Identify(file);
      if (identity.dev != expectedParent.dev) Fail("OWNER_NATIVE_NAMESPACE_UNKNOWN");
      if (expected != null) Match(identity, expected);
      chain.Verify();
      if (directory) {
       // No pathname reopen or chmod. ACL was assigned atomically by NtCreateFile.
       CheckKind(file, true); CheckPrivate(file); Match(Identify(file), identity);
       return new DirectoryResult(identity);
      }
      byte[] old = ReadAll(file);
      if (create && old.Length != 0) Fail("OWNER_NATIVE_IO_UNCERTAIN");
      if (expectedHash != null && Hash(old) != expectedHash) Fail("OWNER_NATIVE_HASH_MISMATCH");
      byte[] wanted = old;
      if (write) {
       if (action == "append") {
        if ((long)old.Length + payload.Length > MaxBytes) Fail("OWNER_NATIVE_LIMIT");
        wanted = new byte[old.Length + payload.Length];
        Buffer.BlockCopy(old, 0, wanted, 0, old.Length);
        Buffer.BlockCopy(payload, 0, wanted, old.Length, payload.Length);
       } else wanted = payload;
       // Recheck all held handles before the first write, not a pathname stat.
       chain.Verify(); CheckKind(file, false); CheckPrivate(file); Match(Identify(file), identity);
       if (!Equal(ReadAll(file), old)) Fail("OWNER_NATIVE_HASH_MISMATCH");
       changed = true;
       Seek(file, action == "append" ? old.Length : 0);
       WriteAll(file, payload);
       if (action != "append" && !Api.SetEndOfFile(file)) Fail("OWNER_NATIVE_IO_UNCERTAIN");
       if (!Api.FlushFileBuffers(file)) Fail("OWNER_NATIVE_IO_UNCERTAIN");
      }
      byte[] readback = ReadAll(file);
      if (!Equal(readback, wanted)) Fail("OWNER_NATIVE_IO_UNCERTAIN");
      chain.Verify(); CheckKind(file, false); CheckPrivate(file); Match(Identify(file), identity);
      FileResult result = new FileResult(); result.identity = identity;
      result.sha256 = Hash(readback); result.bytes = readback.Length; result.data = Convert.ToBase64String(readback);
      return result;
     }
    }
   } catch (SafeFailure) {
    if (changed) Fail("OWNER_NATIVE_IO_UNCERTAIN");
    throw;
   } catch {
    Fail(changed ? "OWNER_NATIVE_IO_UNCERTAIN" : "OWNER_NATIVE_IO_UNKNOWN"); return null;
   }
  }
 }
}
'@

$consoleHostSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace DSHOwnerNative {
 public static class ConsoleHost {
  private const int MaxTransport = 12 * 1024 * 1024;
  private const int MaxAssembly = 512 * 1024;
  private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
  private static readonly HashSet<string> SafeCodes = new HashSet<string>(StringComparer.Ordinal) {
   "OWNER_NATIVE_INPUT", "OWNER_NATIVE_UNSUPPORTED", "OWNER_NATIVE_UNAVAILABLE",
   "OWNER_NATIVE_PROCESS_UNKNOWN", "OWNER_NATIVE_BOOT_UNKNOWN", "OWNER_NATIVE_BOOT_MISMATCH",
   "OWNER_NATIVE_NAMESPACE_UNKNOWN", "OWNER_NATIVE_ACL_UNKNOWN", "OWNER_NATIVE_IDENTITY_MISMATCH",
   "OWNER_NATIVE_HASH_MISMATCH", "OWNER_NATIVE_IO_UNKNOWN", "OWNER_NATIVE_IO_UNCERTAIN",
   "OWNER_NATIVE_LIMIT", "OWNER_NATIVE_GUARD_BUSY", "OWNER_NATIVE_GUARD_UNKNOWN",
   "OWNER_NATIVE_PARENT_UNKNOWN", "OWNER_NATIVE_ANCHOR_UNKNOWN"
  };
  private static Dictionary<string, object> Record(object value) {
   Dictionary<string, object> record = value as Dictionary<string, object>;
   if (record == null) throw new SafeFailure("OWNER_NATIVE_INPUT");
   return record;
  }
  private static object Field(Dictionary<string, object> record, string key) {
   object value;
   return record.TryGetValue(key, out value) ? value : null;
  }
  private static string Text(Dictionary<string, object> record, string key, bool nullable = false) {
   object value = Field(record, key);
   if (nullable && value == null) return null;
   if (!(value is string)) throw new SafeFailure("OWNER_NATIVE_INPUT");
   return (string)value;
  }
  private static int Integer(Dictionary<string, object> record, string key, bool nullable = false) {
   object value = Field(record, key);
   if (nullable && value == null) return -1;
   if (!(value is int) || (int)value < 0) throw new SafeFailure("OWNER_NATIVE_INPUT");
   return (int)value;
  }
  private static FileIdentity FileId(object value) {
   if (value == null) return null;
   Dictionary<string, object> record = Record(value);
   return new FileIdentity { dev = Text(record, "dev"), ino = Text(record, "ino"), birth = Text(record, "birth") };
  }
  private static ProcessIdentity ProcessId(object value) {
   if (value == null) return null;
   Dictionary<string, object> record = Record(value);
   return new ProcessIdentity { protocol = Text(record, "protocol"), platform = Text(record, "platform"),
    pid = (uint)Integer(record, "pid"), birth = Text(record, "birth"), boot = Text(record, "boot"),
    guardScope = Text(record, "guardScope") };
  }
  private static Stream WireInput;
  private static string ReadRequest(bool allowCleanEof = false) {
   // Count raw bytes, not decoded characters: an incomplete UTF8 code point
   // before EOF is a nonempty partial frame, never a clean shutdown.
   using (MemoryStream frame = new MemoryStream(4096)) {
    while (true) {
     int value = WireInput.ReadByte();
     if (value < 0) {
      if (allowCleanEof && frame.Length == 0) return null;
      throw new SafeFailure("OWNER_NATIVE_INPUT");
     }
     if (value == 10) {
      try { return Utf8.GetString(frame.ToArray()); }
      catch (DecoderFallbackException) { throw new SafeFailure("OWNER_NATIVE_INPUT"); }
     }
     if (frame.Length + 1 >= MaxTransport) throw new SafeFailure("OWNER_NATIVE_LIMIT");
     frame.WriteByte((byte)value);
    }
   }
  }
  private static void VerifyImage(Dictionary<string, object> request) {
   // Package cohesion only, NOT executable authentication or a filesystem ACL
   // proof. The enclosing package must be trusted before its EXE is launched.
   int length = Integer(request, "nativeAssemblyBytes");
   string expected = Text(request, "nativeAssemblySha256");
   if (length < 512 || length > MaxAssembly || expected.Length != 64)
    throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
   foreach (char value in expected)
    if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')))
     throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
   string location = Assembly.GetExecutingAssembly().Location;
   if (String.IsNullOrEmpty(location)) throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
   byte[] bytes = new byte[length];
   using (FileStream image = new FileStream(location, FileMode.Open, FileAccess.Read, FileShare.Read)) {
    if (!image.CanSeek || image.Length != length) throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
    int offset = 0;
    while (offset < length) {
     int count = image.Read(bytes, offset, length - offset);
     if (count <= 0) throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
     offset += count;
    }
    if (image.ReadByte() >= 0 || image.Length != length) throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
   }
   using (SHA256 hash = SHA256.Create()) {
    string actual = BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
    if (!String.Equals(actual, expected, StringComparison.Ordinal)) throw new SafeFailure("OWNER_NATIVE_UNAVAILABLE");
   }
  }
  private static object DirectoryBatch(Dictionary<string, object> request) {
   IList entries = Field(request, "directories") as IList;
   if (entries == null || entries.Count < 1 || entries.Count > 128)
    throw new SafeFailure("OWNER_NATIVE_INPUT");
   List<FileIdentity> identities = new List<FileIdentity>();
   for (int i = 0; i < entries.Count; ++i) {
    Dictionary<string, object> entry = Record(entries[i]);
    FileIdentity expected = FileId(Field(entry, "expected"));
    if (expected == null) throw new SafeFailure("OWNER_NATIVE_INPUT");
    // Reuse the complete original no-reparse/NTFS/ACL/identity verification.
    FileIdentity actual = Native.Directory(Text(entry, "path")).identity;
    identities.Add(actual);
    // Preserve the caller's first-mismatch ordering; do not touch later paths.
    if (actual.dev != expected.dev || actual.ino != expected.ino || actual.birth != expected.birth)
     return new Dictionary<string, object> { { "ok", true }, { "identities", identities }, { "mismatchIndex", i } };
   }
   return new Dictionary<string, object> { { "ok", true }, { "identities", identities }, { "mismatchIndex", -1 } };
  }
  private static void Emit(JavaScriptSerializer serializer, object reply) {
   string output = serializer.Serialize(reply);
   if (Utf8.GetByteCount(output) >= MaxTransport) throw new SafeFailure("OWNER_NATIVE_LIMIT");
   Console.Out.WriteLine(output); Console.Out.Flush();
  }
  private static int FixedFailure(Exception exception) {
   string code = "OWNER_NATIVE_UNAVAILABLE";
   for (int depth = 0; depth < 6 && exception != null; ++depth, exception = exception.InnerException) {
    SafeFailure safe = exception as SafeFailure;
    if (safe != null) { if (SafeCodes.Contains(safe.Code)) code = safe.Code; break; }
   }
   try {
    // No exception.Message/ToString(), paths, native diagnostics, or stack traces.
    Console.Out.WriteLine("{\"ok\":false,\"code\":\"" + code + "\"}"); Console.Out.Flush(); return 0;
   } catch { return 1; }
  }
  public static int Main(string[] args) {
   AnchorLease lease = null; bool ready = false;
   try {
    if (args.Length != 0 || IntPtr.Size != 8 || Environment.OSVersion.Platform != PlatformID.Win32NT)
     throw new SafeFailure("OWNER_NATIVE_UNSUPPORTED");
    // The same strict UTF8 TextReader remains Console.In for native keeper EOF.
    // No ReadToEnd, type resolver, cmdlet, source compiler, or argv data channel.
    WireInput = new BufferedStream(Console.OpenStandardInput(), 4096);
    Console.SetIn(new StreamReader(WireInput, Utf8, false, 4096, true));
    Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), Utf8, 4096, true));
    JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = MaxTransport, RecursionLimit = 16 };
    Dictionary<string, object> request;
    try { request = Record(serializer.DeserializeObject(ReadRequest())); }
    catch (SafeFailure) { throw; }
    catch { throw new SafeFailure("OWNER_NATIVE_INPUT"); }
    VerifyImage(request);
    string operation = Text(request, "operation");
    if (operation == "kernelGuard") {
     // Synchronous Main -> ONE Native invocation -> ONE OS owning thread.
     // Native itself exits nonzero on every failure after its ready response.
     Native.ServeKernelGuard(Text(request, "key")); return 0;
    }
    if (operation == "hold" || operation == "holdQueries") {
     IList directories = Field(request, "directories") as IList;
     if (directories == null || directories.Count < 1 || directories.Count > 128)
      throw new SafeFailure("OWNER_NATIVE_INPUT");
     string[] paths = new string[directories.Count]; FileIdentity[] identities = new FileIdentity[directories.Count];
     for (int i = 0; i < directories.Count; ++i) {
      Dictionary<string, object> entry = Record(directories[i]);
      paths[i] = Text(entry, "path"); identities[i] = FileId(Field(entry, "identity"));
     }
     lease = Native.Hold(paths, identities);
     ready = true; // Partial/failed ready output also MUST NOT become exit0.
     Emit(serializer, new Dictionary<string, object> { { "ok", true }, { "ready", true },
      { "processIdentity", lease.processIdentity } });
     if (operation == "holdQueries") {
      // A dedicated read-only extension of this anchor keeper, not a writer.
      // Read itself distinguishes clean frame-boundary EOF from partial
      // frame/UTF8 failure; Peek is not an availability/EOF contract for a pipe.
      // Any failure after ready remains a nonzero exit.
      while (true) {
       string frame = ReadRequest(true);
       if (frame == null) break;
       Dictionary<string, object> query = Record(serializer.DeserializeObject(frame));
       int queryId = Integer(query, "queryId");
       if (queryId < 1) throw new SafeFailure("OWNER_NATIVE_INPUT");
       object result; string queryFailure = null;
       try {
        VerifyImage(query);
        if (Text(query, "operation") != "directoryBatch") throw new SafeFailure("OWNER_NATIVE_INPUT");
        result = DirectoryBatch(query);
       } catch (SafeFailure error) {
        queryFailure = SafeCodes.Contains(error.Code) ? error.Code : "OWNER_NATIVE_UNAVAILABLE";
        result = new Dictionary<string, object> { { "ok", false }, { "code", queryFailure } };
       } catch {
        queryFailure = "OWNER_NATIVE_UNAVAILABLE";
        result = new Dictionary<string, object> { { "ok", false }, { "code", queryFailure } };
       }
       Emit(serializer, new Dictionary<string, object> { { "queryId", queryId }, { "reply", result } });
       if (queryFailure != null) throw new SafeFailure(queryFailure);
      }
     } else if (WireInput.ReadByte() >= 0) throw new SafeFailure("OWNER_NATIVE_ANCHOR_UNKNOWN");
     lease.Verify(); lease.Dispose(); lease = null; return 0;
    }
    // Nonkeepers require EOF BEFORE any native operation or business side effect.
    if (WireInput.ReadByte() >= 0) throw new SafeFailure("OWNER_NATIVE_INPUT");
    object reply;
    switch (operation) {
     case "identity": reply = Native.Identity((uint)Integer(request, "pid")); break;
     case "probe": reply = Native.Probe((uint)Integer(request, "pid"), Text(request, "birth"), Text(request, "boot")); break;
     case "directory": reply = Native.Directory(Text(request, "directory")); break;
     case "persistentDirectory": reply = Native.PersistentDirectory(Text(request, "directory")); break;
     case "directoryBatch": reply = DirectoryBatch(request); break;
     case "file":
      reply = Native.GuardedFileOperation(Text(request, "parent"), FileId(Field(request, "expectedParent")),
       Text(request, "name"), Text(request, "action"), FileId(Field(request, "expected")),
       Text(request, "expectedHash", true), Text(request, "data", true), Integer(request, "length", true),
       Text(request, "ioGuardKey", true), ProcessId(Field(request, "ownerProcess"))); break;
     default: throw new SafeFailure("OWNER_NATIVE_INPUT");
    }
    Emit(serializer, reply); return 0;
   } catch (Exception exception) {
    if (lease != null) { try { lease.Dispose(); } catch { } }
    if (ready) return 1;
    return FixedFailure(exception);
   }
  }
 }
}
'@
