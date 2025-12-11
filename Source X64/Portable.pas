unit Portable;

interface

uses
Windows,
PsApi,
Utils,
Parametrs,
Hook,
Refining;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

var
  Proc : procedure;                 // Процедурная переменная

procedure HookPreferences;

implementation

type

  NTStatus = UINT32;

  // Перечисляемый тип данных для функции GetComputerNameExW
  TComputerNameFormat = (ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsDomain,
                         ComputerNameDnsFullyQualified, ComputerNamePhysicalNetBIOS,
                         ComputerNamePhysicalDnsHostname, ComputerNamePhysicalDnsDomain,
                         ComputerNamePhysicalDnsFullyQualified, ComputerNameMax);  

  // Структура для функции LdrLoadDll и NtCreateKey
  UNICODESTRING = record
  Length :        USHORT ;         // размер строки в байтах без учета символа конца строки
  MaximumLength : USHORT ;         // размер памяти, выделенной для буфера
  Buffer :   PWIDESTRING ;         // буффер - указатель на строку WideString (уникоде строка)
  end;

  // Структура для функции NtCreateKey
  ObjectAttributes = record
  Length: ULONG;
  RootDirectory: THandle;
  var ObjectName: UNICODESTRING;
  Attributes: ULONG;
  SecurityDescriptor: Pointer;
  SecurityQualityOfService: Pointer;
  end;

  // Структура для функции PSStringFromPropertyKey
  PROPERTYKEY = record
  fmtid: TGUID;
  pid: DWORD;
  end;

  // Структура для описания входных и выходных данных
  DATA_BLOB = record
  cbData: DWORD;            // Размер данных в байтах
  pbData: pByte;            // Указатель на первый байт в блоке данных
  end;

  // Структура для описания дополнительных данных шифрования
  CRYPTPROTECT_PROMPTSTRUCT = record
  cbSize: DWORD;            // Размер этой структуры в байтах
  dwPromptFlags: DWORD;     // флаги, указывающие, когда должны отображаться приглашения в пользовательскую область
  hwndApp: HWND;            // Дескриптор окна для родительского окна.
  szPrompt: PWideChar;      // Строка, содержащая текст приглашения, которое должно быть отображено.
  end;

  // Обявление типа фукции с парамеи вызова и возврата соответующими оригинальной функции  UpdateProcThreadAttribute
  UpdProcThrAttr = function (lpAttributeList: Pointer; dwFlags: DWORD; Attribute: DWORD_PTR; lpValue: Pointer;
                             cbSize: SIZE_T; lpPreviousValue: PPointer; lpReturnSize: PSIZE_T): BOOL; stdcall;

  // Обявление типа фукции с парамеи вызова и возврата соответующими оригинальной функции  LoadDll
  LoadDll = function(PathToFile: PWideChar; Flags: DWORD; var ModuleFileName: UNICODESTRING; ModuleHandle: PPointer):NTSTATUS; stdcall;

  // Обявление типа фукции с парамеи вызова и возврата соответующими оригинальной функции  NtCreateKey
  CreateKey= function(KeyHandle : PHANDLE; DesiredAccess : ACCESS_MASK; var ObjectAttributes : ObjectAttributes; TitleIndex:ULONG;
                      var ObjectClass : UNICODESTRING; CreateOptions:ULONG; Disposition:PULONG) : NTSTATUS; stdcall;

  // Обявление типа фукции с параметрами вызова и возврата соответующими оригинальной функции PSStringFromPropertyKey
  PSStringFPropKey = function(const pkey: PROPERTYKEY; psz: PWideChar; cch: INTEGER): HRESULT ; stdcall;

// Объявление константы с именем PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
// с типом данных DWORD и присвоение ей значения в соответствии с WinBase.h
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = DWORD ($00020007);

var
  RawUpdateProcThreadAttribute : UpdProcThrAttr;
  RawCreateKey  : CreateKey;
  RawPSStringFromPropertyKey : PSStringFPropKey;

{
  Описание функций для подмены в системных библиотеках
  kernel32.dll (GetComputerName, GetVolumeInformation, UpdateProcThreadAttribute, CreateDirectoryW в XP)
  kernelbase.dll (CreateDirectoryW в 7-11)
  Advapi32.dll (LogonUserA, LogonUserW)
  Crypt32.dll (CryptProtectData, CryptUnprotectData)
  ntdll.dll (NtCreateKey, LoadDll)
  Propsys.dll (PSStringFromPropertyKey)
}

// Измененная функция GetCommandLineW. Добавляет аргументы в командную строку перед запуском
function CommandLineW: PWideChar;
var
ARG: WideString;
PARAMS : WideString;
I : Integer;

begin
  SetHook(CMDCODE, 0);
  Result := GetCommandLineW;
  SetHook(CMDCODE, 1);
  // Первый параметр - это выполняемая программа, он всегда передаётся в кавычках. Следующие это остальные параметры.
  // Первый параметр нужно исключить.
  ARG := Result;
  I := 2;
  if ARG[1] = '"' then                   // Если в начале кавычка тогда
  begin
    while (ARG[I] <> '"') do inc(I);     // дойти до второй кавычки
    if (ARG[I] = '"') then inc(I);       // если кавычка то перейти за неё
    if (ARG[I] = ' ') then inc(I);       // если пробел то перейти за него
    Delete(ARG, 1, I-1);                 // Исключить первый параметр
  end;
  if ARG <> '' then ARG := ARG + ' ';    // Добавить пробел (пробел - это разделитель между параметрами)
  if (XPOS('-type=', String(ARG)) = 0) and (XPOS('--portable', String(ARG)) = 0) then
  begin
    GetModuleFileName(0, AppPatch, SizeOF(AppPatch));          // Получить полный путь (с именем файла)
    FileName := AppPatch;                                      // Имя выполняемой программы
    ExeDir := GetAPPDir(AppPatch);                             // Получить путь к директории (без имени файла)
    PARAMS := ADDParam(ARG);                                   // Добавить параметры к уже полученным
    PARAMS := '"' + FileName + '"' + ' ' + PARAMS; // Поместить перед всеми параметрами имя выполняемой программы
    Result := PWideChar(PARAMS + #0);                          // Готовый результат
  end;
end;

// Это модифицированная функция для блокировки System.AppUserModel.ID
function StringFromPropertyKey(const pkey: PROPERTYKEY; psz: PWideChar; cch: INTEGER): HRESULT ; stdcall;
begin
  SetHook(PFPCODE, 0);
  Result := RawPSStringFromPropertyKey(pkey, psz, cch);
  SetHook(PFPCODE, 1);
  if (SUCCEEDED(Result)) then
  if (pkey.fmtid.D1 = $9F4C2855) and (pkey.fmtid.D2 = $9F79) and (pkey.fmtid.D3 = $4B39) and (pkey.pid = 5) then
  Result := Longint(-1);
end;

function GetComputerNameA(lpBuffer: PChar; var nSize: DWORD): BOOL; stdcall;
begin
  result := False;
end;

// Модифицированная функция GetComputerNameW
function GetComputerNameW(lpBuffer: PWideChar; var nSize: DWORD): BOOL; stdcall;
var
  RequiredSize: DWORD;
  NameLen: DWORD;
begin
  Result := False;
  if COMPNAME <> '' then                                          // Если имя задано
  begin
    NameLen := Length(COMPNAME);                                  // Определить число символов в имени
    RequiredSize := NameLen + 1;                                  // Расчитать рекомендуемый размер
    if nSize < RequiredSize then                                  // Если на входе размер меньше чем рекомендуемый
    begin
      nSize := RequiredSize;                                      // Передать на выход рекомендуемый размер
      Exit;                                                       // Выйти из функции
    end;
    CopyMemory(lpBuffer, PWideChar(COMPNAME), (NameLen + 1) * 2); // Скопировать в буфер имя с учетом терминального нуля
    nSize := NameLen;                                             // Число символов в имени на выход
    Result := True;
  end;
end;

// Это модифицированная функция-заглушка. Отключает в браузере использование системного DNS-клиента
function GetComputerNameExW(NameType: TComputerNameFormat; lpBuffer: PWideChar; var nSize: DWORD): BOOL; stdcall;
begin
  Result := false;
end;

function GetVolumeInformationA
  (
   lpRootPathName: PChar;                                  // путь к сетевому или локальному тому
   lpVolumeNameBuffer: PChar;                              // буфер в котором будет храниться имя тома
   nVolumeNameSize: DWORD;                                 // размер буфера
   lpVolumeSerialNumber: PDWORD;                           // серийный номер тома
   var lpMaximumComponentLength, lpFileSystemFlags: DWORD; // размер тома и тип файловой системы
   lpFileSystemNameBuffer: PChar;                          // название файловой системы
   nFileSystemNameSize: DWORD                              // размер буфера под название файловой системы
  ): BOOL; stdcall;
begin
  result := False;
end;

function GetVolumeInformationW
  (
   lpRootPathName: PWideChar;                               // путь к сетевому или локальному тому
   lpVolumeNameBuffer: PWideChar;                           // буфер в котором будет храниться имя тома
   nVolumeNameSize: DWORD;                                  // размер буфера
   lpVolumeSerialNumber: PDWORD;                            // серийный номер тома
   var lpMaximumComponentLength, lpFileSystemFlags: DWORD;  // размер тома и тип файловой системы
   lpFileSystemNameBuffer: PWideChar;                       // название файловой системы
   nFileSystemNameSize: DWORD                               // размер буфера под название файловой системы
  ): BOOL; stdcall;
begin
  result := False;
end;

// Функция UpdateProcThreadAttribute модифирована чтобы сбрасывать 
// бит PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ui64 << 44)
// бит PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON (0x00000001ui64 << 28)
function UpdateProcThreadAttribute
  (
   lpAttributeList: Pointer;        // Указатель на список атрибутов
   dwFlags: DWORD;                  // Этот параметр зарезервирован и должен иметь значение 0
   Attribute: DWORD_PTR;            // Ключ атрибута для обновления в списке атрибутов
   lpValue: Pointer;                // Указатель на значение атрибута
   cbSize: SIZE_T;                  // Размер значения атрибута, заданного параметром lpValue
   lpPreviousValue: PPointer;       // Этот параметр зарезервирован и должен иметь значение NULL
   lpReturnSize: PSIZE_T            // Этот параметр зарезервирован и должен иметь значение NULL
  ): BOOL; stdcall;
var
  Buffer : array of byte;
begin
  if (Attribute = PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) and (cbSize >= sizeof(UInt64)) then
  begin
    SetLength(Buffer, cbSize);                     // Задать размер буфера
    CopyMemory(Addr(Buffer[0]), lpValue, cbSize);  // Скопировать в массив значение атрибута из адреса по указателю
    Buffer[5] := Buffer[5] and not (1 shl 4);          // Сбросить бит NON_MICROSOFT_BINARIES_ALWAYS_ON - это пятый бит шестого байта Int64
    Buffer[3] := Buffer[3] and not (1 shl 4);          // Сбросить бит WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON - это пятый бит четвертого байта Int64	
    CopyMemory(lpValue, Addr(Buffer[0]), cbSize);  // Скопировать в адрес по указателю значения из буфера
    Buffer := nil;                                 // Освободить память буфера
  end;
  SetHook(UPTCODE, 0);
  result := RawUpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
  SetHook(UPTCODE, 1);
end;

function LogonUserA(lpszUsername, lpszDomain, lpszPassword: PAnsiChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): BOOL; stdcall;
begin
  phToken := $09051945;
  result := True;
end;

function LogonUserW(lpszUsername, lpszDomain, lpszPassword: PWideChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): BOOL; stdcall;
begin
  phToken := $09051945;
  result := True;
end;

// Модифицированная функция CryptProtectData. Входные данные передаются в выходные без шифрования.
function CryptProtectData  (
                            var pDataIn: DATA_BLOB;                       // указатель на структуру pDataIn типа DATA_BLOB с входными данными.
                            ppszDataDescr: PWideChar;                     // описание данных, этот параметр можно не задавать.
                            var pOptionalEntropy: DATA_BLOB;              // указатель на структуру pOptionalEntropy типа DATA_BLOB. исподбзуется для задания энтропии.
                            pvReserved: Pointer;                          // этот параметр зарезервирован и может не задаваться.
                            var pPromptStruct: CRYPTPROTECT_PROMPTSTRUCT; // указатель на структуру pPromptStruct типа CRYPTPROTECT_PROMPTSTRUCT для ввода доп. пароля для шифрования
                            dwFlags: DWORD;                               // флаги, управляющие процессом шифрования
                            var pDataOut: DATA_BLOB                       // указатель на структуру pDataOut типа DATA_BLOB с выходными данными
                            ): BOOL; stdcall;

begin
  pDataOut.cbData := pDataIn.cbData;                                      // Размер выходных данных равен размеру входных
  pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));       // Выделить фиксированную память для блока выходных данных
  CopyMemory(pDataOut.pbData, pDataIn.pbData, pDataIn.cbData);            // Скопировать входные данные в блок выходных данных
  result := TRUE;
end;

// Модифицированная функция CryptUnprotectData. Входные данные передаются в выходные без дешифрования.
function CryptUnprotectData(
                            var pDataIn: DATA_BLOB;                       // указатель на структуру pDataIn типа DATA_BLOB с входными данными.
                            ppszDataDescr: PWideChar;                     // описание данных, этот параметр можно не задавать.
                            var pOptionalEntropy: DATA_BLOB;              // указатель на структуру pOptionalEntropy типа DATA_BLOB. исподбзуется для задания энтропии.
                            pvReserved: Pointer;                          // этот параметр зарезервирован и может не задаваться.
                            var pPromptStruct: CRYPTPROTECT_PROMPTSTRUCT; // указатель на структуру pPromptStruct типа CRYPTPROTECT_PROMPTSTRUCT для ввода доп. пароля для шифрования
                            dwFlags: DWORD;                               // флаги, управляющие процессом шифрования
                            var pDataOut: DATA_BLOB                       // указатель на структуру pDataOut типа DATA_BLOB с выходными данными
                            ): BOOL; stdcall;
begin
  pDataOut.cbData := pDataIn.cbData;                                      // Размер выходных данных равен размеру входных
  pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));       // Выделить фиксированную память для блока выходных данных
  CopyMemory(pDataOut.pbData, pDataIn.pbData, pDataIn.cbData);            // Скопировать входные данные в блок выходных данных
  result := TRUE;
end;

function RegCreateKeyA(hKey: HKEY; lpSubKey: PAnsiChar; phkResult: PHKEY): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyW(hKey: HKEY; lpSubKey: PWideChar; phkResult: PHKEY): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyExA(hKey: HKEY; lpSubKey: PAnsiChar; Reserved: DWORD; lpClass: PAnsiChar; dwOptions: DWORD; samDesired: REGSAM;
                         lpSecurityAttributes: PSecurityAttributes; phkResult: PHKEY; lpdwDisposition: PDWORD): Longint; stdcall;
begin
  lpdwDisposition := nil;
  Result := 0;
end;

function RegCreateKeyExW(hKey: HKEY; lpSubKey: PWideChar; Reserved: DWORD; lpClass: PWideChar; dwOptions: DWORD; samDesired: REGSAM;
                         lpSecurityAttributes: PSecurityAttributes; phkResult: PHKEY; lpdwDisposition: PDWORD): Longint; stdcall;
begin
  phkResult := nil;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegSetValueA(hKey: HKEY; lpSubKey: PAnsiChar; dwType: DWORD; lpData: PAnsiChar; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegSetValueW(hKey: HKEY; lpSubKey: PWideChar; dwType: DWORD; lpData: PWideChar; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegSetValueExA(hKey: HKEY; lpValueName: PAnsiChar; Reserved: DWORD; dwType: DWORD; lpData: Pointer; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegSetValueExW(hKey: HKEY; lpValueName: PWideChar; Reserved: DWORD; dwType: DWORD; lpData: Pointer; cbData: DWORD): Longint; stdcall;
begin
  Result := 0;
end;

function RegCreateKeyTransactedA(
                                 hKey: HKEY; lpSubKey: PAnsiChar;
                                 Reserved: DWORD; lpClass: PAnsiChar;
                                 dwOptions: DWORD; samDesired: REGSAM;
                                 lpSecurityAttributes: PSecurityAttributes;
                                 var phkResult: HKEY; lpdwDisposition: PDWORD;
                                 hTransaction: DWORD; pExtendedParemeter: Pointer
                                 ): Longint; stdcall;
begin
  phkResult := 0;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegCreateKeyTransactedW(
                                 hKey: HKEY; lpSubKey: PWideChar;
                                 Reserved: DWORD; lpClass: PWideChar;
                                 dwOptions: DWORD; samDesired: REGSAM;
                                 lpSecurityAttributes: PSecurityAttributes;
                                 var phkResult: HKEY; lpdwDisposition: PDWORD;
                                 hTransaction: DWORD; pExtendedParemeter: Pointer
                                 ): Longint; stdcall;
begin
  phkResult := 0;
  lpdwDisposition := nil;
  Result := 0;
end;

function RegNotifyChangeKeyValue(hKey: HKEY; bWatchSubtree: BOOL; dwNotifyFilter: DWORD; hEvent: THandle; fAsynchronus: BOOL): Longint; stdcall;
begin
  Result := 0;
end;

function ReportEventA(hEventLog: THandle; wType, wCategory: Word; dwEventID: DWORD; lpUserSid: Pointer;
                      wNumStrings: Word; dwDataSize: DWORD; lpStrings, lpRawData: Pointer): BOOL; stdcall;
begin
  Result := True;;
end;

function ReportEventW(hEventLog: THandle; wType, wCategory: Word; dwEventID: DWORD; lpUserSid: Pointer;
                      wNumStrings: Word; dwDataSize: DWORD; lpStrings, lpRawData: Pointer): BOOL; stdcall;
begin
  Result := True;
end;

function RegisterEventSourceA(lpUNCServerName, lpSourceName: PAnsiChar): THandle; stdcall;
begin
  Result := 0;
end;

function RegisterEventSourceW(lpUNCServerName, lpSourceName: PWideChar): THandle; stdcall;
begin
  Result := 0;
end;

// Модифицированная функция NtCreateKey для блокировки записи в реестр
function NtCreateKey(
                     KeyHandle : PHANDLE;                    // Указатель на переменную-дескриптор, которая получает дескриптор ключа.
                     DesiredAccess : ACCESS_MASK;            // Указывает значение ACCESS_MASK, которое определяет запрашиваемый доступ к объекту.
                     var ObjectAttributes : ObjectAttributes;// Указатель на структуру ObjectAttributes, которая определяет имя объекта и другие атрибуты.
                     TitleIndex:ULONG;                       // Драйверы устройств и промежуточных устройств устанавливают этот параметр равным нулю.
                     var ObjectClass : UNICODESTRING;        // Указатель на строку UNICODESTRING, содержащую класс объекта ключа.
                     CreateOptions:ULONG;                    // Определяет параметры, применяемые при создании или открытии ключа.
                     Disposition:PULONG                      // указатель на переменную, которая получает значение, указывающее, был ли создан новый ключ или открыт существующий.
                     ): NTSTATUS; stdcall;
begin
  if DesiredAccess = 1 then DesiredAccess := 0;
  if DesiredAccess = 3 then DesiredAccess := 0;
  if DesiredAccess = 514 then DesiredAccess := 0;
  SetHook(KEYCODE, 0);
  Result := RawCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, ObjectClass, CreateOptions, Disposition);
  SetHook(KEYCODE, 1);
end;

// Модифицированная функция CreateDirectoryW для блокировки создания папок из списка
function CreateDirectory(lpPathName: PWideChar; lpSecurityAttributes: PSecurityAttributes): BOOL; stdcall;
var
  PathName : String;
  DirName  : String;
  I: integer;
  Cmp : boolean;
begin
  PathName := PWIDECHAR(lpPathName);                         // Взять имя директории из указателя
  Cmp := False;                                              // Снять флаг
  Result := True;
  if DIROFF = True then for I := 0 to DIRLISTNUM - 1 do      // Цикл сравнения имени директории со списком
  begin
    DirName := BLOCKDIRLIST[i];                              // Имя из списка блокировки в переменную
    if XPOS(DirName, PathName) <> 0 then Cmp := True;        // Если имя совпадает с именем из списка установить флаг
    if Cmp = True then break;                                // Если флаг установлен прервать цикл
  end;
  if XPOS('BrowserMetrics', PathName) <> 0 then Cmp := True;
  // Если флаг не установлен выполнить функции CreateDirectoryW
  SetHook(CRDCODE, 0);
  if Cmp = False then Result := CreateDirectoryW(lpPathName, lpSecurityAttributes);
  SetHook(CRDCODE, 1);
end;

// Модифицированная функция для получения имени файла из его указателя
function GetFinalPathNameByHandleW(hFile: THandle; lpszFilePath: PWidechar; cchFilePath: DWORD; dwFlags: DWORD): DWORD; stdcall;
var
  hFileMap : THandle;
  lpFilename : array of WideChar;
  pMem : pointer;
  NameLen : DWORD;
begin
  NameLen := 0;
  SetLength(lpFilename, cchFilePath);
  hFileMap := CreateFileMapping(hFile, nil, PAGE_READONLY, 0, 0, nil); // Создать объект "проецируемый в память файл"
  if (hFileMap <> 0) then // Если объект создан, тогда
  begin
    pMem := MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1); // отобразить файл в адресном пространстве (чтобы получить имя файла)
    if (pMem <> nil) then // если успешно, тогда
      begin
        NameLen := GetMappedFileNameW(GetCurrentProcess, pMem, ADDR(lpFilename[0]), cchFilePath); // получить имя файла в виде пути к имени устройства
        if (NameLen <> 0) then CopyMemory(lpszFilePath, ADDR(lpFilename[0]), (NameLen + 1) * 2);  // если имя получено скопировать его и завершающий символ в указатель
        UnmapViewOfFile(pMem); // Отключить отображение файла в адресном пространстве
      end;
    CloseHandle(hFileMap); // Освободить идентификатор объекта
  end;
  Result := NameLen;
end;

// Модифицированная функция SHGetFolderPathW для блокировки доступа к специальным папкам
function SHGetFolderPathW(hwnd: HWND; csidl: Integer; hToken: THandle; dwFlags: DWord; pszPath: PWideChar): HRESULT; stdcall;
begin
  if SPECFOLDER = '' then SPECFOLDER := 'nul';
  CopyMemory(pszPath, PwideChar(WideString(SPECFOLDER)), (Length(SPECFOLDER) + 1) * 2);
  if SPECFOLDER = 'nul' then Result := E_ABORT  else Result := S_OK;
end;

procedure HookPreferences;
var
  DLLHandle : THandle;                                                  // Переменная типа THandle
  SysPatch  : array [0..MAX_PATH] of Char;                              // Переменная для хранения пути
  FileName  : string;                                                   // Переменная для хранения полного имени файла
begin
  GetSystemDirectory(SysPatch, SizeOf(SysPatch));                       // Определить Путь к системной директории
  // Перехват вызова функций из kernel32.dll
  DLLHandle := GetModuleHandle('kernel32.dll');
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameA');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameA));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetComputerNameW));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL

  Addr(Proc) := GetProcAddress(DLLHandle, 'GetCommandLineW');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CommandLineW), 1);                          // Подмена адреса точки входа функции в процессе на адрес функции из DLL

  if DNSOFF = True then
  begin
    // При установке заглушки на функцию GetComputerNameExW
    // в браузере активируется функция Getaddrinfo даже если
    // включена системная служба DNS-клиента
    Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameExW');      // Определить адрес функции
    CodeHook(Addr(Proc), ADDR(GetComputerNameExW));                     // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;

  Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationA');     // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetVolumeInformationA));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationW');     // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetVolumeInformationW));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  if OS > 1 then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'UpdateProcThreadAttribute'); // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(UpdateProcThreadAttribute), 2);             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawUpdateProcThreadAttribute) := ADDR(Proc);                     // Присвоить адрес функции RawUpdateProcThreadAttribute
  end;

  Addr(Proc) := GetProcAddress(DLLHandle, 'CreateDirectoryW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CreateDirectory), 4);                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL

  if (OS > 1) and (RMDISK = TRUE) then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'GetFinalPathNameByHandleW'); // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(GetFinalPathNameByHandleW));                // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;

  // Перехват вызова функций из advapi32.dll
  DLLHandle := GetModuleHandle('advapi32.dll');                         // Получить идентификатор
  if (DLLHandle = 0) then                                               // Если идентификатор не получен
  begin
    FileName :=  SysPatch + '\advapi32.dll';                            // Получить полное имя файла
    DLLHandle := LoadLibrary(pchar(FileName));                          // Загрузить библиотеку и получить её идентификатор
  end;  
  Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserA');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserW');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  // Перехват вызова функций записи в реестр 
  if REGOFF = TRUE then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyA');             // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyA));                            // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyW');             // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyW));                            // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyExA');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyExA));                          // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyExW');           // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyExW));                          // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueA');              // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueA));                             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueW');              // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueW));                             // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueExA');            // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueExA));                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegSetValueExW');            // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegSetValueExW));                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyTransactedA');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyTransactedA));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  if OS > 1 then begin
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegCreateKeyTransactedW');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegCreateKeyTransactedW));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;
  Addr(Proc) := GetProcAddress(DLLHandle, 'RegNotifyChangeKeyValue');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(RegNotifyChangeKeyValue));                  // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;

  // Перехват вызова функций записи событий в системный журнал
  ADDR(Proc) := GetProcAddress(DLLHandle, 'ReportEventA');              // Определить адрес функции
  CodeHook(ADDR(Proc), ADDR(ReportEventA));                             // Подмена адреса функции в процессе на адрес функции из DLL
  ADDR(Proc) := GetProcAddress(DLLHandle, 'ReportEventW');              // Определить адрес функции
  CodeHook(ADDR(Proc), ADDR(ReportEventW));                             // Подмена адреса функции в процессе на адрес функции из DLL
  ADDR(Proc) := GetProcAddress(DLLHandle, 'RegisterEventSourceA');      // Определить адрес функции
  CodeHook(ADDR(Proc), ADDR(RegisterEventSourceA));                     // Подмена адреса функции в процессе на адрес функции из DLL
  ADDR(Proc) := GetProcAddress(DLLHandle, 'RegisterEventSourceW');      // Определить адрес функции
  CodeHook(ADDR(Proc), ADDR(RegisterEventSourceW));                     // Подмена адреса функции в процессе на адрес функции из DLL

  // Перехват вызова функций из Crypt32.dll
  FileName :=  SysPatch + '\Crypt32.dll';                               // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'CryptProtectData');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CryptProtectData));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  Addr(Proc) := GetProcAddress(DLLHandle, 'CryptUnprotectData');        // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(CryptUnprotectData));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL

  // Перехват вызова функции NtCreateKey.
  if REGOFF = TRUE then begin
  DLLHandle := GetModuleHandle('ntdll.dll');                            // DLLHandle = дескриптор модуля (адрес по которому он загружен)
  Addr(Proc) := GetProcAddress(DLLHandle, 'NtCreateKey');               // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(NtCreateKey), 3);                           // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RawCreateKey) := ADDR(Proc);                                     // Присвоить адрес функции RawCreateKey
  end;

  // Перехват вызова функции SHGetFolderPathW
  if SPFOLD = TRUE then begin
  FileName := SysPatch + '\SHELL32.dll';                                // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  Addr(Proc) := GetProcAddress(DLLHandle, 'SHGetFolderPathW');          // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(SHGetFolderPathW));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  end;
  
  // Перехват вызова функций из Propsys.dll
  if AIDOFF = TRUE then begin
  DLLHandle := GetModuleHandle('Propsys.dll');                          // Получить идентификатор
  if (DLLHandle = 0) then                                               // Если идентификатор не получен
  begin
    FileName :=  SysPatch + '\Propsys.dll';                             // Получить полное имя файла
    DLLHandle := LoadLibrary(pchar(FileName));                          // Загрузить библиотеку и получить её идентификатор
  end;
  Addr(Proc) := GetProcAddress(DLLHandle, 'PSStringFromPropertyKey');   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(StringFromPropertyKey), 8);                 // Подмена адреса точки входа функции в процессе на адрес функции из DLL
  ADDR(RAWPSStringFromPropertyKey) := ADDR(Proc);                       // Присвоить адрес функции RAWPSStringFromPropertyKey
  end;

  if (REFINE = TRUE) or (BCTOFF = TRUE) or (ECHOFF = TRUE) then begin
  //Подключение библиотеки WS2_32.dll
  FileName := SysPatch + '\WS2_32.dll';                                 // Получить полное имя файла
  DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
  // Импорт функции closesocket
  ADDR(closesocket) := GetProcAddress(DLLHandle, 'closesocket');
  
  if REFINE = TRUE then begin
  //Перехват функции WSASend
  ADDR(Proc) := GetProcAddress(DLLHandle, 'WSASend');                   // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(WSASend), 5);                               // Подмена адреса функции
  ADDR(RAWWSASend) := ADDR(Proc);
  
  // Перехват функции getaddrinfo
  ADDR(Proc) := GetProcAddress(DLLHandle, 'getaddrinfo');
  CodeHook(Addr(Proc), ADDR(Getaddrinfo), 7);
  ADDR(RAWGetaddrinfo) := ADDR(Proc);
  end;
  
  if (BCTOFF = TRUE) or (ECHOFF = TRUE) then begin
  // Перехват функции setsockopt
  Addr(Proc) := GetProcAddress(DLLHandle, 'setsockopt');                // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(Setsockopt), 6);                            // Подмена адреса функции
  ADDR(RAWSetsockopt) := ADDR(Proc);

  // Перехват функции Listen
  ADDR(Proc) := GetProcAddress(DLLHandle, 'listen');                    // Определить адрес функции
  CodeHook(Addr(Proc), ADDR(Listen));
  end;
  end;
  
  end;
end.