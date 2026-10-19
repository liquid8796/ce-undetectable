unit AntiCheatDetector;

{$mode objfpc}{$H+}

interface

uses
  windows, sysutils, classes, jwawindows;

type
  TAntiCheatType = (
    acNone,
    acWarden,
    acVAC,
    acEAC,
    acBattlEye,
    acXIGNCODE,
    acNProtect,
    acRicochet,
    acVanguard,
    acFaceit,
    acESEA
  );

  TAntiCheatInfo = record
    AType: TAntiCheatType;
    IsKernelLevel: Boolean;
    IsHypervisorLevel: Boolean;
  end;

const
  AntiCheatNames: array[TAntiCheatType] of string = (
    'None', 'Warden', 'VAC', 'EasyAntiCheat', 'BattlEye',
    'XIGNCODE3', 'nProtect GameGuard', 'Ricochet', 'Vanguard', 'Faceit', 'ESEA'
  );

  ACEACDrivers: array[0..2] of string = ('EasyAntiCheat.sys', 'EasyAntiCheat_EOS.sys', 'EasyAntiCheat');
  ACBEDrivers: array[0..2] of string = ('BEDaisy.sys', 'BEDaisy', 'be_driver.sys');
  ACXIGNDrivers: array[0..2] of string = ('x3.xem', 'xnl.sys', 'xhunter1.sys');
  ACRicochetDrivers: array[0..1] of string = ('randgrid.sys', 'shmvcb.sys');

  ACEACProcesses: array[0..2] of string = ('EasyAntiCheat.exe', 'EasyAntiCheat_EOS.exe', 'eac_launcher.exe');
  ACBEProcesses: array[0..2] of string = ('BEService.exe', 'BEService_x64.exe', 'be_client.exe');
  ACVanguardProcesses: array[0..2] of string = ('vgc.exe', 'vgtray.exe', 'vgk.exe');
  ACXIGNProcesses: array[0..2] of string = ('x3.xem', 'XIGNCode3', 'xcoronahost.xem');
  ACFaceitProcesses: array[0..2] of string = ('faceit.exe', 'faceitclient.exe', 'faceit_acs.exe');
  ACESEAProcesses: array[0..1] of string = ('eseaclient.exe', 'eslwire.exe');

function DetectAntiCheat: TAntiCheatInfo;
function GetAntiCheatName(AType: TAntiCheatType): string;
function ShouldUseKernelBridge(AC: TAntiCheatType): Boolean;

implementation

uses
  SyscallGateway;

const
  SystemModuleInformation = 11;  // SYSTEM_INFORMATION_CLASS

type
  TRTLProcessModuleInfo = packed record
    Section: Pointer;
    MappedBase: Pointer;
    ImageBase: Pointer;
    ImageSize: ULONG;
    Flags: ULONG;
    LoadOrderIndex: USHORT;
    InitOrderIndex: USHORT;
    LoadCount: USHORT;
    OffsetToFileName: USHORT;
    FullPathName: array[0..255] of Char;
  end;

  TRTLProcessModules = packed record
    NumberOfModules: ULONG;
    Modules: array[0..0] of TRTLProcessModuleInfo;
  end;
  PRTLProcessModules = ^TRTLProcessModules;

function IsDriverLoaded(DriverName: string): Boolean;
var
  buf: Pointer;
  bufSize: ULONG;
  status: NTSTATUS;
  retLen: ULONG;
  pMods: PRTLProcessModules;
  pMod: ^TRTLProcessModuleInfo;
  modName: PChar;
  i: Integer;
begin
  Result := False;
  bufSize := 1024 * 1024; // 1MB buffer
  GetMem(buf, bufSize);

  status := SyscallNtQuerySystemInformation(SystemModuleInformation, buf, bufSize, @retLen);
  if status < 0 then
  begin
    FreeMem(buf);
    Exit;
  end;

  pMods := PRTLProcessModules(buf);
  for i := 0 to pMods^.NumberOfModules - 1 do
  begin
    pMod := @pMods^.Modules[i];
    modName := PChar(@pMod^.FullPathName[pMod^.OffsetToFileName]);
    if SameText(modName, DriverName) then
    begin
      Result := True;
      Break;
    end;
  end;

  FreeMem(buf);
end;

function IsProcessRunning(ProcName: string): Boolean;
var
  hSnapshot: THandle;
  pe: TProcessEntry32;
begin
  Result := False;
  hSnapshot := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if hSnapshot = INVALID_HANDLE_VALUE then Exit;

  pe.dwSize := SizeOf(pe);
  if Process32First(hSnapshot, pe) then
    repeat
      if SameText(pe.szExeFile, ProcName) then
      begin
        Result := True;
        Break;
      end;
    until not Process32Next(hSnapshot, pe);

  CloseHandle(hSnapshot);
end;

function HasAnyProcess(const Names: array of string): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(Names) do
    if IsProcessRunning(Names[i]) then Exit(True);
  Result := False;
end;

function HasAnyDriver(const Names: array of string): Boolean;
var
  i: Integer;
begin
  for i := 0 to High(Names) do
    if IsDriverLoaded(Names[i]) then Exit(True);
  Result := False;
end;

function DetectAntiCheat: TAntiCheatInfo;
begin
  FillChar(Result, SizeOf(Result), 0);

  if HasAnyProcess(ACVanguardProcesses) then
  begin
    Result.AType := acVanguard;
    Result.IsKernelLevel := True;
    Result.IsHypervisorLevel := True;
    Exit;
  end;

  if HasAnyDriver(ACBEDrivers) then
  begin
    Result.AType := acBattlEye;
    Result.IsKernelLevel := True;
    Exit;
  end;

  if HasAnyDriver(ACEACDrivers) then
  begin
    Result.AType := acEAC;
    Result.IsKernelLevel := True;
    Exit;
  end;

  if HasAnyDriver(ACRicochetDrivers) then
  begin
    Result.AType := acRicochet;
    Result.IsKernelLevel := True;
    Exit;
  end;

  if HasAnyProcess(ACFaceitProcesses) then
  begin
    Result.AType := acFaceit;
    Result.IsKernelLevel := True;
    Exit;
  end;

  if HasAnyProcess(ACESEAProcesses) then
  begin
    Result.AType := acESEA;
    Result.IsKernelLevel := True;
    Exit;
  end;

  if HasAnyProcess(ACXIGNProcesses) or HasAnyDriver(ACXIGNDrivers) then
  begin
    Result.AType := acXIGNCODE;
    Exit;
  end;

  if HasAnyProcess(ACEACProcesses) then
  begin
    Result.AType := acEAC;
    Exit;
  end;

  if HasAnyProcess(ACBEProcesses) then
  begin
    Result.AType := acBattlEye;
    Exit;
  end;

  if IsProcessRunning('Hearthstone.exe') or
     IsProcessRunning('Wow.exe') or
     IsProcessRunning('Overwatch.exe') or
     IsProcessRunning('Diablo IV.exe') then
    Result.AType := acWarden;
end;

function GetAntiCheatName(AType: TAntiCheatType): string;
begin
  Result := AntiCheatNames[AType];
end;

function ShouldUseKernelBridge(AC: TAntiCheatType): Boolean;
begin
  case AC of
    acEAC, acBattlEye, acRicochet, acNProtect, acFaceit, acESEA, acVanguard:
      Result := True;
    else
      Result := False;
  end;
end;

end.
