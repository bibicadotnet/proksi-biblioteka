library version;

uses
  Windows,
  PSAPI,
  ShellAPI,
  SecurePreferences in 'SecurePreferences.pas';

  {$R version.res}
  {$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}


VAR
AppPatch: array [0..MAX_PATH] of Char;
Proc : array [1..8] of Procedure;  // массив типа Procedure
FileName  : string;                // Переменная для хранения полного имени файла
APPDIR    : string;
PARAMS    : string;                // Переменная для хранения параметров
ExeMain   : procedure;
  
  OLDCODE : packed record // Структура для формирования функции-моста
  CALL        : Byte;     // Поле для записи опкода инструкции CALL    | $E8
  CALLOFFSET  : DWORD;    // Поле для записи аргумента инструкции CALL | DWORD
  JMP         : Byte;     // Поле для записи опкода инструкции JMP     | $E9
  JMPOFFSET   : DWORD;    // Поле для записи аргумента инструкции JMP  | DWORD
  end;

// Описание функций для метода dll wraper
// Функции представляют собой джампы на адреса функций системного файла version.dll.
// Адреса функций определяются динамически.
procedure GetFileVersionInfoSizeW; stdcall; begin asm jmp dword ptr [proc + 0 * 4]; end; end;
procedure GetFileVersionInfoW; stdcall; begin asm jmp dword ptr [proc + 1 * 4]; end; end;
procedure VerQueryValueW; stdcall; begin asm jmp dword ptr [proc + 2 * 4]; end; end;
procedure GetFileVersionInfoSizeA; stdcall; begin asm jmp dword ptr [proc + 3 * 4]; end; end;
procedure GetFileVersionInfoA; stdcall; begin asm jmp dword ptr [proc + 4 * 4]; end; end;
procedure VerQueryValueA; stdcall; begin asm jmp dword ptr [proc + 5 * 4]; end; end;
procedure GetFileVersionInfoExW; stdcall; begin asm jmp dword ptr [proc + 6 * 4]; end; end;
procedure GetFileVersionInfoSizeExW; stdcall; begin asm jmp dword ptr [proc + 7 * 4]; end; end;

// Объявление списока экспортируемых функций
exports
GetFileVersionInfoSizeW name 'GetFileVersionInfoSizeW',
GetFileVersionInfoW name 'GetFileVersionInfoW',
VerQueryValueW name 'VerQueryValueW',
GetFileVersionInfoSizeA name 'GetFileVersionInfoSizeA',
GetFileVersionInfoA name 'GetFileVersionInfoA',
VerQueryValueA name 'VerQueryValueA',
GetFileVersionInfoExW name 'GetFileVersionInfoExW',
GetFileVersionInfoSizeExW name 'GetFileVersionInfoSizeExW';

// Функция для определения пути к программе
function GetAPPDir(APP : string): string;
var
  Len: LongWord;
begin
  Len := Length(APP);
  while (Len <> 0) and (APP[Len] <> '\') and (APP[Len] <> '/') do Dec(Len);
  Result := Copy(APP, 0, Len);
end;

// Функция для добавления параметров запуска
function ADDParam(ARGS : string) : string;
begin
 APPDIR := GetAPPDir(AppPatch);
 ARGS := ARGS + '--portable' + ' ';
 ARGS := ARGS + '--disable-features=RendererCodeIntegrity,FlashDeprecationWarning' + ' ';
 ARGS := ARGS + '--simulate-critical-update' + ' ';
 ARGS := ARGS + '--user-data-dir=' + '"' + APPDIR + 'User Data' + '"' + ' ';
 ARGS := ARGS + '--disk-cache-dir=' + '"' + APPDIR + 'Cache' + '"' + ' ';
 ARGS := ARGS + '--disable-logging' + ' ';
 //ARGS := ARGS + '--no-first-run' + ' ';
 //ARGS := ARGS + '--ppapi-flash-path=' + '"' + APPDIR + 'plugins\pepflashplayer32.dll' + ' ';
 //ARGS := ARGS + '--test-type' + ' ';
 //ARGS := ARGS + '--no-sandbox' + ' ';
 RESULT := ARGS;
end;

procedure PORTABLE(PARAM:string);
var
  ShellExecuteInfo: TShellExecuteInfo;
begin
 // Получить полное именя файла с использованием API функции GetModuleFileName
 // Если вместо 0 вписать hInstance, то будет путь к имени DLL файла
 GetModuleFileName(0, AppPatch, SizeOF(AppPatch));
 FileName := AppPatch;
 PARAMS := ADDParam(PARAM);
 APPDIR := GetAPPDir(AppPatch);
 // MessageBox(0, pchar(PARAMS), 'Параметры перед запуском', MB_OK);
 // Заполнение структуры для запуска программы
 FillChar(ShellExecuteInfo, SizeOf(TShellExecuteInfo), 0) ;                // Очистить структуру от случайных данных
 ShellExecuteInfo.cbSize := sizeof(TShellExecuteInfo);                     // Размер структуры в байтах
 ShellExecuteInfo.fMask := SEE_MASK_NOCLOSEPROCESS or SEE_MASK_FLAG_NO_UI; // Комбинация флагов, определяющих используемую часть структуры
 ShellExecuteInfo.lpVerb := 'open';                                        // Строка, определяющее действие с файлом. "open" запускает исполняемый файл.
 ShellExecuteInfo.lpFile := pchar(FileName);                               // Имя файла (полный путь к файлу)
 ShellExecuteInfo.lpDirectory := pchar(APPDIR);                            // Рабочая директория программы
 ShellExecuteInfo.nShow := SW_SHOWNORMAL;                                  // Способ отображения окна
 ShellExecuteInfo.lpParameters := pchar(PARAMS);                           // Параметры.
 if ShellExecuteEx(ADDR(ShellExecuteInfo)) then ExitProcess(0);            // Запустить программу.
end;

// Определить параметры коммандной строки
procedure REDIRECT;
var
ARG: String;
i: integer;
begin
 // ParamCount - это число параметров. ParamStr(i) - это параметр номер i.
 // Нулевой параметр - это выполняемая программа, следующие это параметры.
 ARG := '';
 // Перевести все параметры в одну строку
 for i := 1 to ParamCount do ARG := ARG + ParamStr(i) + ' ';
 // Если в командной строке нет параметра -type= и --portable тогда выполнить PORTABLE
 if (POS('-type=', ARG) = 0) and (POS('--portable', ARG) = 0) then PORTABLE(ARG);
 HookPreferences;
 ExeMain;
end;

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer);
var
  // структура для обычного пехвата через JMP NEAR OFFSET
  CODE   : packed record
  JMP    : Byte;
  OFFSET : DWORD; end;
  Protect, VALUE : DWORD;
const
  HANDLE = DWORD(-1);
begin
  CODE.JMP := $E9;
  CODE.OFFSET := DWORD (NewProcAddress) - DWORD (OldProcAddress) - 5;
  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 5, PAGE_EXECUTE_READWRITE, Protect) then exit;
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  // Вместо HANDLE можно вписать INVALID_HANDLE_VALUE - это идентификатор текущего процесса.
  WriteProcessMemory(HANDLE, OldProcAddress, Addr(CODE), 5, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 5, Protect, Protect);
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

// Определение и подмена адреса точки входа
procedure RedirectEP;
var
MI   : MODULEINFO;    // Переменная типа MODULEINFO, MODULEINFO - это структура, которая содержит поле EntryPoint
EntryADDR : PBYTE;    // Переменная указатель для хранения адреса точки входа
Protect   : DWORD;
VALUE     : DWORD;
const
  HANDLE = DWORD(-1);
begin
 GetModuleInformation(GetCurrentProcess, GetModuleHandle(NIL), Addr(MI), sizeof(MODULEINFO)); // Считать информацию о родительском процессе
 EntryADDR := MI.EntryPoint;             // Считать в переменную адрес точки входа из поля EntryPoint структуры MI
 // Изменить параметры доступа к памяти где расположена структура OLDCODE
 if not VirtualProtect(ADDR(OLDCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
 // Считать пять байт исходной функции в структуру OLDCODE
 ReadProcessMemory(HANDLE, EntryADDR, Addr(OLDCODE), 5, VALUE);
 OLDCODE.CALL := $E8;
 OLDCODE.JMP := $E9;
 // Расчитать смещение и записать его значение в поле структуры
 OLDCODE.CALLOFFSET := OLDCODE.CALLOFFSET + CODEOFFSET(LONGWORD(ADDR(OLDCODE)), LONGWORD(EntryADDR)) + 5;
 OLDCODE.JMPOFFSET := CODEOFFSET(LONGWORD(ADDR(OLDCODE)), LONGWORD(EntryADDR));
 CodeHook(EntryADDR, ADDR(REDIRECT));    // Подмена адреса точки входа в процессе на адрес функции из DLL.
 ADDR(ExeMain) := ADDR(OLDCODE);         // Назначить адрес процедуры ExeMain равным адресу структуры OLDCODE
 //HookPreferences;
end;

// Обертка для переадресации экспортируемых функций
procedure RedirectEXAT;
var
DLLHandle : THandle;                         // Переменная типа THandle (соответствует LONGWORD)
SysPatch  : array [0..MAX_PATH] of Char;     // Переменная для хранения пути
begin
 GetSystemDirectory(SysPatch, SizeOf(SysPatch));                          // Определить Путь к системной директории
 FileName :=  SysPatch + '\version.dll';                                  // Получить полное имя файла
 DLLHandle := LoadLibrary(pchar(FileName));                               // Загрузить библиотеку и получить её идентификатор
 Addr(proc[1]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoSizeW');   // Определить адрес функции
 Addr(proc[2]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoW');       // Определить адрес функции
 Addr(proc[3]) := GetProcAddress(DLLHandle, 'VerQueryValueW');            // Определить адрес функции
 Addr(proc[4]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoSizeA');   // Определить адрес функции
 Addr(proc[5]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoA');       // Определить адрес функции
 Addr(proc[6]) := GetProcAddress(DLLHandle, 'VerQueryValueA');            // Определить адрес функции
 Addr(proc[7]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoExW');     // Определить адрес функции
 Addr(proc[8]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoSizeExW'); // Определить адрес функции
end;

// Основная стартовая функция
procedure DllMain(fdwReason: DWORD);
begin
 if (fdwReason = DLL_PROCESS_ATTACH) then
  begin
   DisableThreadLibraryCalls(hInstance); // отключить уведомления DLL_THREAD_ATTACH и DLL_THREAD_DETACH
   RedirectEXAT;                         // Шаг 1. Выполнить переадресацию функций экспорта
   RedirectEP;                           // Шаг 2. Выполнить переадресацию точки входа
  end;
end;

// Этот код выполняется каждый раз при при загрузке библиотеки
begin
 if Addr(DllProc) = nil then    // Исли переменной DllProc не присвоено никакое значение
  begin
   DllProc := Addr(DllMain);    // Присвоить переменной DllProc адрес процедуры DllMain
   DllMain(DLL_PROCESS_ATTACH); // Выполнить процедуру DllMain с параметром DLL_PROCESS_ATTACH
 end;
end.
