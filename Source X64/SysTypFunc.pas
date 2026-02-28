unit SysTypFunc;

interface

{ *Описание типов данных из модуля Windows и PSAPI* }
Const
  kernel32  = 'kernel32.dll';
  PAGE_EXECUTE_READWRITE = $40;
  IMAGE_FILE_DEBUG_STRIPPED = $0200;
  IMAGE_FILE_LINE_NUMS_STRIPPED = $0004;
  IMAGE_FILE_LOCAL_SYMS_STRIPPED = $0008;
  MAX_PATH = 260;
  INVALID_HANDLE_VALUE = THandle(-1);
  LMEM_FIXED = 0;
  PAGE_READONLY = 2;
  SECTION_MAP_READ = 4;
  FILE_MAP_READ = SECTION_MAP_READ;
  E_ABORT = HRESULT($80004004);

  DLL_PROCESS_ATTACH = 1;
  DLL_THREAD_ATTACH = 2;
  DLL_THREAD_DETACH = 3;
  DLL_PROCESS_DETACH = 0;

Type
  ULONG_PTR = NativeUInt;
  DWORD_PTR = ULONG_PTR;
  SIZE_T = ULONG_PTR;
  PSIZE_T = ^SIZE_T;
  USHORT = Word;
  UINT_PTR = UIntPtr;

  DWORD = LongWord;
  BOOL = LongBool;
  ULONG = Cardinal;
  HWND = UINT_PTR;
  PHandle = ^THandle;
  ACCESS_MASK = DWORD;
  PULONG = ^ULONG;
  PDWORD = ^DWORD;
  UINT = LongWord;
  HLOCAL = THandle;
  HKEY = UINT_PTR;
  PHKEY = ^HKEY;
  REGSAM = ACCESS_MASK;
  LPCSTR = PAnsiChar;
  FARPROC = Pointer;

  PSecurityAttributes = ^TSecurityAttributes;
  _SECURITY_ATTRIBUTES = record
    nLength: DWORD;
    lpSecurityDescriptor: Pointer;
    bInheritHandle: BOOL;
  end;
  TSecurityAttributes = _SECURITY_ATTRIBUTES;
  SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES;

  _OSVERSIONINFOA = record
    dwOSVersionInfoSize: DWORD;
    dwMajorVersion: DWORD;
    dwMinorVersion: DWORD;
    dwBuildNumber: DWORD;
    dwPlatformId: DWORD;
    szCSDVersion: array[0..127] of AnsiChar; { Maintenance AnsiString for PSS usage }
  end;

  _OSVERSIONINFOW = record
    dwOSVersionInfoSize: DWORD;
    dwMajorVersion: DWORD;
    dwMinorVersion: DWORD;
    dwBuildNumber: DWORD;
    dwPlatformId: DWORD;
    szCSDVersion: array[0..127] of WideChar; { Maintenance UnicodeString for PSS usage }
  end;

  TOSVersionInfoA = _OSVERSIONINFOA;
  TOSVersionInfoW = _OSVERSIONINFOW;
  TOSVersionInfo = TOSVersionInfoW;

  _FILETIME = record
    dwLowDateTime: DWORD;
    dwHighDateTime: DWORD;
  end;

  TFileTime = _FILETIME;

  _WIN32_FIND_DATAA = record
    dwFileAttributes: DWORD;
    ftCreationTime: TFileTime;
    ftLastAccessTime: TFileTime;
    ftLastWriteTime: TFileTime;
    nFileSizeHigh: DWORD;
    nFileSizeLow: DWORD;
    dwReserved0: DWORD;
    dwReserved1: DWORD;
    cFileName: array[0..MAX_PATH - 1] of AnsiChar;
    cAlternateFileName: array[0..13] of AnsiChar;
  end;

  _WIN32_FIND_DATAW = record
    dwFileAttributes: DWORD;
    ftCreationTime: TFileTime;
    ftLastAccessTime: TFileTime;
    ftLastWriteTime: TFileTime;
    nFileSizeHigh: DWORD;
    nFileSizeLow: DWORD;
    dwReserved0: DWORD;
    dwReserved1: DWORD;
    cFileName: array[0..MAX_PATH - 1] of WideChar;
    cAlternateFileName: array[0..13] of WideChar;
  end;

  TWin32FindDataA = _WIN32_FIND_DATAA;
  TWin32FindDataW = _WIN32_FIND_DATAW;
  TWin32FindData = TWin32FindDataW;

  TGetMappedFileNameW = function (hProcess: THandle; lpv: Pointer; lpFilename: PWideChar; nSize: DWORD): DWORD stdcall;

function ReadProcessMemory(hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesRead: SIZE_T): BOOL; stdcall;
function ReadProcessMemory; external kernel32 name 'ReadProcessMemory';

function VirtualProtect(lpAddress: Pointer; dwSize: SIZE_T; flNewProtect: DWORD; lpflOldProtect: Pointer): BOOL; stdcall; overload;
function VirtualProtect(lpAddress: Pointer; dwSize: SIZE_T; flNewProtect: DWORD; var OldProtect: DWORD): BOOL; stdcall; overload;
function VirtualProtect(lpAddress: Pointer; dwSize: SIZE_T; flNewProtect: DWORD; lpflOldProtect: Pointer): BOOL; external kernel32 name 'VirtualProtect';
function VirtualProtect(lpAddress: Pointer; dwSize: SIZE_T; flNewProtect: DWORD; var OldProtect: DWORD): BOOL; external kernel32 name 'VirtualProtect';

function WriteProcessMemory(hProcess: THandle; const lpBaseAddress: Pointer; lpBuffer: Pointer; nSize: SIZE_T; var lpNumberOfBytesWritten: SIZE_T): BOOL; stdcall;
function WriteProcessMemory; external kernel32 name 'WriteProcessMemory';

function GetVersionEx(var lpVersionInformation: TOSVersionInfo): BOOL; stdcall;
function GetVersionEx(var lpVersionInformation: TOSVersionInfo): BOOL; external kernel32 name 'GetVersionExW';

function GetFullPathName(lpFileName: PWideChar; nBufferLength: DWORD; lpBuffer: PWideChar; var lpFilePart: PWideChar): DWORD; stdcall;
function GetFullPathName; external kernel32 name 'GetFullPathNameW';

function FindNextFile(hFindFile: THandle; var lpFindFileData: TWIN32FindData): BOOL; stdcall;
function FindNextFile; external kernel32 name 'FindNextFileW';

function FindClose(hFindFile: THandle): BOOL; stdcall;
function FindClose; external kernel32 name 'FindClose';

function FindFirstFile(lpFileName: PWideChar; var lpFindFileData: TWIN32FindData): THandle; stdcall;
function FindFirstFile; external kernel32 name 'FindFirstFileW';

function GetModuleFileName(hModule: HINST; lpFilename: PWideChar; nSize: DWORD): DWORD; stdcall;
function GetModuleFileName; external kernel32 name 'GetModuleFileNameW';

function DeleteFile(lpFileName: PWideChar): BOOL; stdcall;
function DeleteFile; external kernel32 name 'DeleteFileW';

function RemoveDirectory(lpPathName: PWideChar): BOOL; stdcall;
function RemoveDirectory; external kernel32 name 'RemoveDirectoryW';

function GetCommandLineW: PWideChar; stdcall;
function GetCommandLineW; external kernel32 name 'GetCommandLineW';

function LocalAlloc(uFlags, uBytes: SIZE_T): HLOCAL; stdcall;
function LocalAlloc; external kernel32 name 'LocalAlloc';

function CreateDirectoryW(lpPathName: PWideChar; lpSecurityAttributes: PSecurityAttributes): BOOL; stdcall;
function CreateDirectoryW; external kernel32 name 'CreateDirectoryW';

function CreateFileMapping(hFile: THandle; lpFileMappingAttributes: PSecurityAttributes;
                           flProtect, dwMaximumSizeHigh, dwMaximumSizeLow: DWORD; lpName: PWideChar): THandle; stdcall;
function CreateFileMapping; external kernel32 name 'CreateFileMappingW';

function MapViewOfFile(hFileMappingObject: THandle; dwDesiredAccess: DWORD;
                       dwFileOffsetHigh, dwFileOffsetLow: DWORD; dwNumberOfBytesToMap: SIZE_T): Pointer; stdcall;
function MapViewOfFile; external kernel32 name 'MapViewOfFile';

function GetCurrentProcess: THandle; stdcall;
function GetCurrentProcess; external kernel32 name 'GetCurrentProcess';

function UnmapViewOfFile(lpBaseAddress: Pointer): BOOL; stdcall;
function UnmapViewOfFile; external kernel32 name 'UnmapViewOfFile';

function CloseHandle(hObject: THandle): BOOL; stdcall;
function CloseHandle; external kernel32 name 'CloseHandle';

function GetSystemDirectory(lpBuffer: PWideChar; uSize: UINT): UINT; stdcall;
function GetSystemDirectory; external kernel32 name 'GetSystemDirectoryW';

function GetModuleHandle(lpModuleName: PWideChar): HMODULE; stdcall;
function GetModuleHandle; external kernel32 name 'GetModuleHandleW';

function GetProcAddress(hModule: HMODULE; lpProcName: LPCSTR): FARPROC; stdcall;
function GetProcAddress(hModule: HMODULE; lpProcName: LPCSTR): FARPROC; external kernel32 name 'GetProcAddress';

function LoadLibrary(lpLibFileName: PWideChar): HMODULE; stdcall;
function LoadLibrary; external kernel32 name 'LoadLibraryW';

function Succeeded(Status: HRESULT): BOOL; inline;
procedure CopyMemory(Destination: Pointer; Source: Pointer; Length: NativeUInt);
function GetMappedFileNameW(hProcess: THandle; lpv: Pointer; lpFilename: PWideChar; nSize: DWORD): DWORD;

{ *Описание типов данных из модуля Windows и PSAPI* }

implementation

var
  hPSAPI: THandle;
  GetMappedFileName: TGetMappedFileNameW;

function Succeeded(Status: HRESULT): BOOL;
begin
  Result := Status and HRESULT($80000000) = 0;
end;

procedure CopyMemory(Destination: Pointer; Source: Pointer; Length: NativeUInt);
begin
  Move(Source^, Destination^, Length);
end;

function CheckPSAPILoaded: Boolean;
begin
  if hPSAPI = 0 then
  begin
    hPSAPI := LoadLibrary('PSAPI.dll');
    if hPSAPI < 32 then
    begin
      hPSAPI := 0;
      Result := False;
      Exit;
    end;
    ADDR(GetMappedFileName) := GetProcAddress(hPSAPI, 'GetMappedFileNameW');
  end;
  Result := True;
end;

function GetMappedFileNameW(hProcess: THandle; lpv: Pointer; lpFilename: PWideChar; nSize: DWORD): DWORD;
begin
  if CheckPSAPILoaded then Result := GetMappedFileName(hProcess, lpv, lpFileName, nSize) else Result := 0;
end;

end.
