unit SyscallGateway;

{$mode objfpc}{$H+}

interface

uses
  {$ifdef windows}
  jwawindows, windows, sysutils, classes;
  {$endif}

function SyscallReadProcessMemory(hProcess: THandle; lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesRead: SIZE_T): BOOL; stdcall;
function SyscallWriteProcessMemory(hProcess: THandle; lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesWritten: SIZE_T): BOOL; stdcall;
function SyscallVirtualQueryEx(hProcess: THandle; lpAddress: Pointer; var lpBuffer: TMemoryBasicInformation; dwLength: DWORD): DWORD; stdcall;
function SyscallOpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
function SyscallCloseHandle(hObject: THandle): BOOL; stdcall;
function SyscallNtQuerySystemInformation(SystemInformationClass: DWORD;
  SystemInformation: Pointer; SystemInformationLength: ULONG;
  ReturnLength: PULONG): NTSTATUS; stdcall;

procedure InitSyscallNumbers;
function AreSyscallsReady: Boolean;

implementation

var
  g_SyscallNtOpenProcess: WORD;
  g_SyscallNtReadVirtualMemory: WORD;
  g_SyscallNtWriteVirtualMemory: WORD;
  g_SyscallNtQueryVirtualMemory: WORD;
  g_SyscallNtClose: WORD;
  g_SyscallNtQuerySystemInformation: WORD;
  g_SyscallsReady: Boolean = False;

type
  PImageDosHeader = ^TImageDosHeader;
  TImageDosHeader = packed record
    e_magic: WORD;
    e_cblp: WORD;
    e_cp: WORD;
    e_crlc: WORD;
    e_cparhdr: WORD;
    e_minalloc: WORD;
    e_maxalloc: WORD;
    e_ss: WORD;
    e_sp: WORD;
    e_csum: WORD;
    e_ip: WORD;
    e_cs: WORD;
    e_lfarlc: WORD;
    e_ovno: WORD;
    e_res: array[0..3] of WORD;
    e_oemid: WORD;
    e_oeminfo: WORD;
    e_res2: array[0..9] of WORD;
    e_lfanew: LONGINT;
  end;

  TImageNtHeaders = packed record
    Signature: DWORD;
    FileHeader: TImageFileHeader;
    OptionalHeader: TImageOptionalHeader64;
  end;
  PImageNtHeaders = ^TImageNtHeaders;

  TSectionHeader = packed record
    Name: array[0..7] of Byte;
    VirtualSize: DWORD;
    VirtualAddress: DWORD;
    SizeOfRawData: DWORD;
    PointerToRawData: DWORD;
    PointerToRelocations: DWORD;
    PointerToLinenumbers: DWORD;
    NumberOfRelocations: WORD;
    NumberOfLinenumbers: WORD;
    Characteristics: DWORD;
  end;
  PSectionHeader = ^TSectionHeader;

function RvaToFileOffset(BaseAddr: PByte; RVA: DWORD): DWORD;
var
  NtHeaders: ^TImageNtHeaders;
  Section: ^TSectionHeader;
  i: Integer;
begin
  Result := 0;
  NtHeaders := PImageNtHeaders(BaseAddr + PImageDosHeader(BaseAddr)^.e_lfanew);
  Section := PSectionHeader(PByte(NtHeaders) + SizeOf(TImageNtHeaders));
  for i := 0 to NtHeaders^.FileHeader.NumberOfSections - 1 do
  begin
    if (RVA >= Section^.VirtualAddress) and
       (RVA < Section^.VirtualAddress + Section^.VirtualSize) then
    begin
      Result := RVA - Section^.VirtualAddress + Section^.PointerToRawData;
      Exit;
    end;
    Inc(Section);
  end;
end;

function ExtractSyscallNumber(FileData: PByte; FileSize: DWORD;
  FunctionName: PAnsiChar): WORD;
var
  DosHeader: PImageDosHeader;
  NtHeaders: ^TImageNtHeaders;
  ExportDir: TImageExportDirectory;
  ExportDirRVA: DWORD;
  ExportDirFOA: DWORD;
  Names: PDWORD;
  Functions: PDWORD;
  Ordinals: PUSHORT;
  FuncRVA: DWORD;
  FuncFOA: DWORD;
  i: Integer;
  NameStr: PAnsiChar;
  p: PByte;
  j: Integer;
begin
  Result := 0;
  if (FileData = nil) or (FileSize < SizeOf(TImageDosHeader)) then Exit;
  DosHeader := PImageDosHeader(FileData);
  if DosHeader^.e_magic <> $5A4D then Exit;

  NtHeaders := PImageNtHeaders(FileData + DosHeader^.e_lfanew);
  if NtHeaders^.Signature <> $4550 then Exit;

  ExportDirRVA := NtHeaders^.OptionalHeader.DataDirectory[0].VirtualAddress;
  if ExportDirRVA = 0 then Exit;

  ExportDirFOA := RvaToFileOffset(FileData, ExportDirRVA);
  if ExportDirFOA = 0 then Exit;

  ExportDir := PImageExportDirectory(FileData + ExportDirFOA)^;

  Names := PDWORD(FileData + RvaToFileOffset(FileData, ExportDir.AddressOfNames));
  Functions := PDWORD(FileData + RvaToFileOffset(FileData, ExportDir.AddressOfFunctions));
  Ordinals := PUSHORT(FileData + RvaToFileOffset(FileData, ExportDir.AddressOfNameOrdinals));

  for i := 0 to ExportDir.NumberOfNames - 1 do
  begin
    NameStr := PAnsiChar(FileData + RvaToFileOffset(FileData, Names^));
    if StrComp(NameStr, FunctionName) = 0 then
    begin
      FuncRVA := Functions^;
      FuncFOA := RvaToFileOffset(FileData, FuncRVA);
      if FuncFOA = 0 then Exit;

      p := FileData + FuncFOA;

      // Scan for: mov eax, XX; (optional test); syscall
      // Pattern: B8 XX 00 00 00 ... 0F 05
      for j := 0 to 64 do
      begin
        if (p[j] = $B8) then
        begin
          // Found mov eax, imm32
          Result := PWORD(@p[j+1])^;
        end;
        if (p[j] = $0F) and (p[j+1] = $05) then
        begin
          // Found syscall, return the last mov eax value seen
          Exit;
        end;
      end;
      Break;
    end;
    Inc(Names);
    Inc(Functions);
    Inc(Ordinals);
  end;
end;

procedure InitSyscallNumbers;
var
  fs: TFileStream;
  FileData: PByte;
  FileSize: DWORD;
  NtdllPath: string;
begin
  if g_SyscallsReady then Exit;

  NtdllPath := '';
  {$ifdef cpu64}
  NtdllPath := 'C:\Windows\System32\ntdll.dll';
  {$else}
  NtdllPath := 'C:\Windows\SysWOW64\ntdll.dll';
  {$endif}

  FileData := nil;
  FileSize := 0;

  if FileExists(NtdllPath) then
  begin
    fs := TFileStream.Create(NtdllPath, fmOpenRead or fmShareDenyNone);
    FileSize := fs.Size;
    FileData := GetMem(FileSize);
    fs.Read(FileData^, FileSize);
    fs.Free;

    g_SyscallNtOpenProcess := ExtractSyscallNumber(FileData, FileSize, 'NtOpenProcess');
    g_SyscallNtReadVirtualMemory := ExtractSyscallNumber(FileData, FileSize, 'NtReadVirtualMemory');
    g_SyscallNtWriteVirtualMemory := ExtractSyscallNumber(FileData, FileSize, 'NtWriteVirtualMemory');
    g_SyscallNtQueryVirtualMemory := ExtractSyscallNumber(FileData, FileSize, 'NtQueryVirtualMemory');
    g_SyscallNtClose := ExtractSyscallNumber(FileData, FileSize, 'NtClose');
    g_SyscallNtQuerySystemInformation := ExtractSyscallNumber(FileData, FileSize, 'NtQuerySystemInformation');

    FreeMem(FileData);
  end;

  // fallback: well-known syscall numbers for Windows 10/11 x64
  if g_SyscallNtOpenProcess = 0 then
    g_SyscallNtOpenProcess := $26;
  if g_SyscallNtReadVirtualMemory = 0 then
    g_SyscallNtReadVirtualMemory := $3F;
  if g_SyscallNtWriteVirtualMemory = 0 then
    g_SyscallNtWriteVirtualMemory := $3A;
  if g_SyscallNtQueryVirtualMemory = 0 then
    g_SyscallNtQueryVirtualMemory := $23;
  if g_SyscallNtClose = 0 then
    g_SyscallNtClose := $0F;
  if g_SyscallNtQuerySystemInformation = 0 then
    g_SyscallNtQuerySystemInformation := $36;

  g_SyscallsReady := True;
end;

function AreSyscallsReady: Boolean;
begin
  Result := g_SyscallsReady;
end;

// Direct syscall implementations using inline assembly
// x64 calling convention: rcx, rdx, r8, r9 for first 4 args
// For syscall: mov r10, rcx; mov eax, syscall_num; syscall; ret

{$ifdef cpu64}

function SyscallOpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
var
  hProcess: THandle;
  objAttr: packed record
    Length: ULONG;
    RootDirectory: THandle;
    ObjectName: Pointer;
    Attributes: ULONG;
    SecurityDescriptor: Pointer;
    SecurityQualityOfService: Pointer;
  end;
  clientId: packed record
    UniqueProcess: THandle;
    UniqueThread: THandle;
  end;
  dwPid: DWORD;
  dwAccess: DWORD;
begin
  dwAccess := dwDesiredAccess;
  dwPid := dwProcessId;
  hProcess := 0;

  FillChar(objAttr, SizeOf(objAttr), 0);
  objAttr.Length := SizeOf(objAttr);
  objAttr.Attributes := $40; // OBJ_CASE_INSENSITIVE

  FillChar(clientId, SizeOf(clientId), 0);
  clientId.UniqueProcess := dwPid;

  asm
    lea rcx, [hProcess]
    mov edx, dwAccess
    lea r8, [objAttr]
    lea r9, [clientId]
    mov r10, rcx
    movzx eax, word [g_SyscallNtOpenProcess]
    syscall
  end;

  Result := hProcess;
end;

function SyscallReadProcessMemory(hProcess: THandle; lpBaseAddress: Pointer;
  lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesRead: SIZE_T): BOOL; stdcall;
var
  status: NTSTATUS;
begin
  lpNumberOfBytesRead := 0;
  status := 0;

  asm
    mov r10, rcx
    movzx eax, word [g_SyscallNtReadVirtualMemory]
    syscall
    mov status, eax
  end;

  Result := (status >= 0);
end;

function SyscallWriteProcessMemory(hProcess: THandle; lpBaseAddress: Pointer;
  lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesWritten: SIZE_T): BOOL; stdcall;
var
  status: NTSTATUS;
begin
  lpNumberOfBytesWritten := 0;
  status := 0;

  asm
    mov r10, rcx
    movzx eax, word [g_SyscallNtWriteVirtualMemory]
    syscall
    mov status, eax
  end;

  Result := (status >= 0);
end;

function SyscallVirtualQueryEx(hProcess: THandle; lpAddress: Pointer;
  var lpBuffer: TMemoryBasicInformation; dwLength: DWORD): DWORD; stdcall;
var
  status: NTSTATUS;
  ReturnLength: SIZE_T;
  bufPtr: Pointer;
begin
  bufPtr := @lpBuffer;
  ReturnLength := 0;
  status := 0;

  asm
    mov r10, rcx
    // rdx already = lpAddress (correct)
    mov r8, 0              // MemoryBasicInformation
    mov r9, bufPtr         // pointer to output buffer
    // push 6th param: ReturnLength
    lea rax, [ReturnLength]
    push rax
    // 5th param: dwLength
    mov eax, dwLength
    push rax
    sub rsp, $20           // shadow space for x64 syscall
    movzx eax, word [g_SyscallNtQueryVirtualMemory]
    syscall
    add rsp, $30           // 0x20 shadow + 0x10 two pushes
    mov status, eax
  end;

  if status >= 0 then
    Result := ReturnLength
  else
    Result := 0;
end;

function SyscallCloseHandle(hObject: THandle): BOOL; stdcall;
var
  status: NTSTATUS;
begin
  status := 0;

  asm
    mov r10, rcx
    movzx eax, word [g_SyscallNtClose]
    syscall
    mov status, eax
  end;

  Result := (status >= 0);
end;

function SyscallNtQuerySystemInformation(SystemInformationClass: DWORD;
  SystemInformation: Pointer; SystemInformationLength: ULONG;
  ReturnLength: PULONG): NTSTATUS; stdcall;
var
  status: NTSTATUS;
begin
  status := 0;
  asm
    mov r10, rcx
    movzx eax, word [g_SyscallNtQuerySystemInformation]
    syscall
    mov status, eax
  end;
  Result := status;
end;

{$else cpu64}
// 32-bit fallback: use regular API for now (syscall via int 2e / sysenter is fragile)
// ponytail: 32-bit games are rare for this use case

function SyscallOpenProcess(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwProcessId: DWORD): THandle; stdcall;
begin
  Result := windows.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
end;

function SyscallReadProcessMemory(hProcess: THandle; lpBaseAddress: Pointer;
  lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesRead: SIZE_T): BOOL; stdcall;
begin
  Result := windows.ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
end;

function SyscallWriteProcessMemory(hProcess: THandle; lpBaseAddress: Pointer;
  lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesWritten: SIZE_T): BOOL; stdcall;
begin
  Result := windows.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
end;

function SyscallVirtualQueryEx(hProcess: THandle; lpAddress: Pointer;
  var lpBuffer: TMemoryBasicInformation; dwLength: DWORD): DWORD; stdcall;
begin
  Result := windows.VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
end;

function SyscallCloseHandle(hObject: THandle): BOOL; stdcall;
begin
  Result := windows.CloseHandle(hObject);
end;

{$endif cpu64}

end.
