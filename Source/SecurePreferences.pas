unit SecurePreferences;

interface

uses
Windows;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure HookPreferences;

implementation

type
// Объявление перечисляемого типа данных с именем COMPUTER_NAME_FORMAT
 COMPUTER_NAME_FORMAT = (ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsDomain, ComputerNameDnsFullyQualified,
                         ComputerNamePhysicalNetBIOS, ComputerNamePhysicalDnsHostname, ComputerNamePhysicalDnsDomain,
                         ComputerNamePhysicalDnsFullyQualified, ComputerNameMax);

 // Структура для описания входных и выходных данных
 DATA_BLOB = record
   cbData: DWORD;         // Размер данных в байтах
   pbData: pByte; end;    // Указатель на первый байт в блоке данных

  // Структура для описания дополнительных данных шифрования
 CRYPTPROTECT_PROMPTSTRUCT = record
   cbSize: DWORD;          // Размер этой структуры в байтах
   dwPromptFlags: DWORD;   // флаги, указывающие, когда должны отображаться приглашения в пользовательскую область
   hwndApp: HWND;          // Дескриптор окна для родительского окна.
   szPrompt: PWideChar; end; // Строка, содержащая текст приглашения, которое должно быть отображено.

 // Обявление типа фукции с парамеи вызова и возврата соответующии оригинальной функции  UpdateProcThreadAttribute
 UpdProcThrAttr = function (lpAttributeList: Pointer; dwFlags: DWORD; Attribute: DWORD; lpValue: Pointer;
                            cbSize: integer; lpPreviousValue: PPointer; lpReturnSize: PInteger): INTEGER; stdcall;

// Объявить константу с именем PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
// с типом данных DWORD и присвоить ей значение в соответствии с WinBase.h
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = DWORD ($00020007);

var

Proc : procedure;
RawUpdateProcThreadAttribute : UpdProcThrAttr;

 OLDCODE : packed record              // Структура для формирования функции-моста
 DATA        : array [0..4] of byte;  // Массив для оригинального началом перехватываемой функции
 JMP         : Byte;                  // Поле для записи опкода инструкции JMP     | $E9
 JMPOFFSET   : DWORD;                 // Поле для записи аргумента инструкции JMP  | DWORD
 end;

// Описание функций для подмены в системных библиотеках
// kernel32.dll (GetComputerName, GetVolumeInformation, UpdateProcThreadAttribute)
// Advapi32.dll (LogonUserA, LogonUserW)
// Crypt32.dll (CryptProtectData, CryptUnprotectData)

function GetComputerNameA(lpBuffer: PChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetComputerNameW(lpBuffer: PWideChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetComputerNameExA(NameType: COMPUTER_NAME_FORMAT; lpBuffer: PChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
end;

function GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT; lpBuffer: PChar; var nSize: DWORD): INTEGER; stdcall;
begin
  result := 0;
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
): INTEGER; stdcall;
begin
  result := 0;
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
): INTEGER; stdcall;
begin
  result := 0;
end;

// Функция UpdateProcThreadAttribute модифирована чтобы сбрасывать бит PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
function UpdateProcThreadAttribute
 (
  lpAttributeList: Pointer;        // Указатель на список атрибутов
  dwFlags: DWORD;                  // Этот параметр зарезервирован и должен иметь значение 0
  Attribute: DWORD;                // Ключ атрибута для обновления в списке атрибутов
  lpValue: Pointer;                // Указатель на значение атрибута
  cbSize: Integer;                 // Размер значения атрибута, заданного параметром lpValue
  lpPreviousValue: PPointer;       // Этот параметр зарезервирован и должен иметь значение NULL
  lpReturnSize: PInteger           // Этот параметр зарезервирован и должен иметь значение NULL
 ): INTEGER; stdcall;
var
Buffer : array of byte;
begin
  if (Attribute = PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) and (cbSize >= sizeof(UInt64)) then
  begin
   SetLength(Buffer, cbSize);                     // Задать размер буфера
   CopyMemory(Addr(Buffer[0]), lpValue, cbSize);  // Скопировать в массив значение атрибута из указателя
   Buffer[5] := Buffer[5] and (0 shl 4);          // Сбросить бит MICROSOFT_BINARIES_ALWAYS_ON - это пятый бит шестого байта Int64 $100000000000
   CopyMemory(lpValue, Addr(Buffer[0]), cbSize);  // Скопировать в указатель значения из буфера
   Buffer := nil;                                 // Освободить память буфера
  end;
  result := RawUpdateProcThreadAttribute(lpAttributeList, dwFlags, Attribute, lpValue, cbSize, lpPreviousValue, lpReturnSize);
end;

function LogonUserA(lpszUsername, lpszDomain, lpszPassword: PAnsiChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): DWORD; stdcall;
begin
  phToken := $09051945;
  result := $09051945;
end;

function LogonUserW(lpszUsername, lpszDomain, lpszPassword: PWideChar; dwLogonType, dwLogonProvider: DWORD; var phToken: THandle): DWORD; stdcall;
begin
 phToken := $09051945;
 result := $09051945;
end;

// Реализация перехвата этих двух функций не выполнена и не требуется
function CryptProtectData  (
                            var pDataIn: DATA_BLOB;                       // указатель на структуру pDataIn типа DATA_BLOB с входными данными.
                            ppszDataDescr: PWideChar;                     // описание данных, этот параметр можно не задавать.
                            var pOptionalEntropy: DATA_BLOB;              // указатель на структуру pOptionalEntropy типа DATA_BLOB. исподбзуется для задания энтропии.
                            pvReserved: Pointer;                          // этот параметр зарезервирован и может не задаваться.
                            var pPromptStruct: CRYPTPROTECT_PROMPTSTRUCT; // указатель на структуру pPromptStruct типа CRYPTPROTECT_PROMPTSTRUCT для ввода доп. пароля для шифрования
                            dwFlags: DWORD;                               // флаги, управляющие процессом шифрования
                            var pDataOut: DATA_BLOB                       // указатель на структуру pDataOut типа DATA_BLOB с выходными данными
                            ): BOOL; stdcall;
var
Buffer : array of byte;
begin
   pDataOut.cbData := pDataIn.cbData;                                    // Размер выходных данных равен размеру входных
   SetLength(Buffer, pDataIn.cbData);                                    // Задать размер буфера равным размеру входных данных
   CopyMemory(Addr(Buffer[0]), pDataIn.pbData, pDataIn.cbData);          // Скопировать в массив входные данные
   pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));     // Выделить фиксированную память для блока выходных данных
   CopyMemory(pDataOut.pbData, Addr(Buffer[0]), pDataIn.cbData);         // Скопировать из массива в блок выходных данных
   Buffer := nil;                                                        // Освободить память буфера
   result := TRUE;
end;

function CryptUnprotectData(
                            var pDataIn: DATA_BLOB;                       // указатель на структуру pDataIn типа DATA_BLOB с входными данными.
                            ppszDataDescr: PWideChar;                     // описание данных, этот параметр можно не задавать.
                            var pOptionalEntropy: DATA_BLOB;              // указатель на структуру pOptionalEntropy типа DATA_BLOB. исподбзуется для задания энтропии.
                            pvReserved: Pointer;                          // этот параметр зарезервирован и может не задаваться.
                            var pPromptStruct: CRYPTPROTECT_PROMPTSTRUCT; // указатель на структуру pPromptStruct типа CRYPTPROTECT_PROMPTSTRUCT для ввода доп. пароля для шифрования
                            dwFlags: DWORD;                               // флаги, управляющие процессом шифрования
                            var pDataOut: DATA_BLOB                       // указатель на структуру pDataOut типа DATA_BLOB с выходными данными
                            ): BOOL; stdcall;
var
Buffer : array of byte;
begin
   pDataOut.cbData := pDataIn.cbData;                                     // Размер выходных данных равен размеру входных
   SetLength(Buffer, pDataOut.cbData);                                    // Задать размер буфера равным размеру входных данных
   CopyMemory(Addr(Buffer[0]), pDataIn.pbData, pDataIn.cbData);           // Скопировать в массив входные данные
   pDataOut.pbData := PBYTE(LocalAlloc(LMEM_FIXED, pDataIn.cbData));      // Выделить фиксированную память для блока выходных данных
   CopyMemory(pDataOut.pbData, Addr(Buffer[0]), pDataIn.cbData);          // Скопировать из массива в блок выходных данных
   Buffer := nil;                                                         // Освободить память буфера
   result := TRUE;
end;

// Функция расчета смещения
function CODEOFFSET(NEWADDR, OLDADDR :DWORD):DWORD;
begin
 if(OLDADDR < NEWADDR) then
 begin
   Result := NEWADDR - OLDADDR;
   Result := $FFFFFFFF - Result;
   Result := Result - 4;
  end
  else begin
   Result := OLDADDR - NEWADDR;
   Result := Result - 5;
  end;
end;

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer);
var
  // структура для обычного перехвата через JMP NEAR OFFSET
  CODE   : packed record
  JMP    : Byte;
  OFFSET : DWORD; end;
  Protect, VALUE : DWORD;
const
  HANDLE = DWORD(-1);                                              // Константа идентификатор текущего процесса
begin
  CODE.JMP := $E9;
  CODE.OFFSET := DWORD (NewProcAddress) - DWORD (OldProcAddress) - 5;
  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 5, PAGE_EXECUTE_READWRITE, Protect) then exit;
  // Записать в память процесса с идентификатором HANDLE в адрес по указателю из OldProcAddress данные из CODE в размере 5 байт
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  WriteProcessMemory(HANDLE, OldProcAddress, Addr(CODE), 5, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 5, Protect, Protect);
end;

procedure HookPreferences;
var
 DLLHandle : THandle;                                                  // Переменная типа THandle (соответствует LONGWORD)
 SysPatch  : array [0..MAX_PATH] of Char;                              // Переменная для хранения пути
 FileName  : string;
 Protect   : DWORD;
 VALUE     : DWORD;
const
  HANDLE = DWORD(-1);
begin
 GetSystemDirectory(SysPatch, SizeOf(SysPatch));                       // Определить Путь к системной директории
 // Перехват вызова функций из kernel32.dll
 FileName :=  SysPatch + '\kernel32.dll';                              // Получить полное имя файла
 DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
 Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameA');          // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(GetComputerNameA));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameW');          // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(GetComputerNameW));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameExA');        // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(GetComputerNameExA));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'GetComputerNameExW');        // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(GetComputerNameExW));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationA');     // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(GetVolumeInformationA));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'GetVolumeInformationW');     // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(GetVolumeInformationW));                    // Подмена адреса точки входа функции в процессе на адрес функции из DLL.

 Addr(Proc) := GetProcAddress(DLLHandle, 'UpdateProcThreadAttribute'); // Определить адрес функции
 // Схранить начало исходной функци в структуру OLDCODE
 if not VirtualProtect(ADDR(OLDCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
 ReadProcessMemory(HANDLE, Addr(Proc), ADDR(OLDCODE), 5, VALUE);
 OLDCODE.JMP := $E9;
 OLDCODE.JMPOFFSET := CODEOFFSET(LONGWORD(ADDR(OLDCODE)), LONGWORD(ADDR(Proc)));
 ADDR(RawUpdateProcThreadAttribute) := ADDR(OLDCODE);                  // Присвоить адрес функции RawUpdateProcThreadAttribute
 CodeHook(Addr(Proc), ADDR(UpdateProcThreadAttribute));                // Подмена адреса точки входа функции в процессе на адрес функции из DLL.

 // Перехват вызова функций из advapi32.dll
 FileName :=  SysPatch + '\advapi32.dll';                              // Получить полное имя файла
 DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
 Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserA');                // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'LogonUserW');                // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(LogonUserW));                               // Подмена адреса точки входа функции в процессе на адрес функции из DLL.

 // Перехват вызова функций из Crypt32.dll
 FileName :=  SysPatch + '\Crypt32.dll';                               // Получить полное имя файла
 DLLHandle := LoadLibrary(pchar(FileName));                            // Загрузить библиотеку и получить её идентификатор
 Addr(Proc) := GetProcAddress(DLLHandle, 'CryptProtectData');          // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(CryptProtectData));                         // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 Addr(Proc) := GetProcAddress(DLLHandle, 'CryptUnprotectData');        // Определить адрес функции
 CodeHook(Addr(Proc), ADDR(CryptUnprotectData));                       // Подмена адреса точки входа функции в процессе на адрес функции из DLL.
 end;

end.
