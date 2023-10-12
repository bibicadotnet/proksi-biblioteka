library version;

uses
  Windows,
  PSAPI,
  ShellAPI,
  SecurePreferences,
  Hook;

{$R version.res}
{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

VAR
  AppPatch: array [0..MAX_PATH] of Char;
  Proc : array [1..8] of Procedure;  // массив типа Procedure
  FileName  : string;                // Переменная для хранения полного имени файла
  APPDIR    : string;                // Переменная для хранения пути к программе
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
  Len: DWORD;
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
  if (POS('--user-data-dir=', ARGS) = 0) then ARGS := ARGS + '--user-data-dir=' + '"' + APPDIR + 'User Data' + '"' + ' ';
  if (POS('--disk-cache-dir=', ARGS) = 0) then ARGS := ARGS + '--disk-cache-dir=' + '"' + APPDIR + 'Cache' + '"' + ' ';
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
  // MessageBox(0, pchar(PARAMS), 'Параметры перед запуском', MB_OK);       // Вывод окна перед запуском. Для отладки
  // Заполнение структуры для запуска программы
  FillChar(ShellExecuteInfo, SizeOf(TShellExecuteInfo), 0) ;                // Очистить структуру от случайных данных
  ShellExecuteInfo.cbSize := sizeof(TShellExecuteInfo);                     // Размер структуры в байтах
  ShellExecuteInfo.fMask := SEE_MASK_NOCLOSEPROCESS or SEE_MASK_FLAG_NO_UI; // Комбинация флагов, определяющих используемую часть структуры
  ShellExecuteInfo.lpVerb := 'open';                                        // Строка, определяющее действие с файлом. 'open' запускает исполняемый файл
  ShellExecuteInfo.lpFile := pchar(FileName);                               // Имя файла (полный путь к файлу)
  ShellExecuteInfo.lpDirectory := pchar(APPDIR);                            // Рабочая директория программы
  ShellExecuteInfo.nShow := SW_SHOWNORMAL;                                  // Способ отображения окна
  ShellExecuteInfo.lpParameters := pchar(PARAMS);                           // Параметры
  if ShellExecuteEx(ADDR(ShellExecuteInfo)) then ExitProcess(0);            // Запустить программу
end;

// Определить параметры коммандной строки, отключить шифрование и запустить программу
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
  // Если в командной строке нет параметров -type= и --portable тогда выполнить процедуру PORTABLE
  if (POS('-type=', ARG) = 0) and (POS('--portable', ARG) = 0) then PORTABLE(ARG);
  HookPreferences;
  ExeMain;
end;

// Определение и подмена адреса точки входа
procedure RedirectEP;
var
  MI   : MODULEINFO;    // Переменная типа MODULEINFO, MODULEINFO - это структура, которая содержит поле EntryPoint
  EntryADDR : PBYTE;    // Переменная указатель на адреса точки входа
  Protect   : DWORD;    // Переменная для хранения параметров доступа к странице памяти
  VALUE     : DWORD;    // Переменная для функции WriteProcessMemory
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
  OLDCODE.CALLOFFSET := OLDCODE.CALLOFFSET + CODEOFFSET(DWORD(ADDR(OLDCODE)), DWORD(EntryADDR)) + 5;
  OLDCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(OLDCODE)), DWORD(EntryADDR));
  CodeHook(EntryADDR, ADDR(REDIRECT));    // Подмена адреса точки входа в процессе на адрес функции из DLL.
  ADDR(ExeMain) := ADDR(OLDCODE);         // Назначить адрес процедуры ExeMain равным адресу структуры OLDCODE
end;

// Обертка для переадресации экспортируемых функций
procedure RedirectEXAT;
var
  DLLHandle : THandle;                         // Переменная типа THandle (соответствует DWORD)
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
   DisableThreadLibraryCalls(hInstance); // Отключить уведомления DLL_THREAD_ATTACH и DLL_THREAD_DETACH
   RedirectEXAT;                         // Шаг 1. Выполнить переадресацию функций экспорта
   RedirectEP;                           // Шаг 2. Выполнить переадресацию точки входа
  end;
end;

// Этот код выполняется каждый раз при при загрузке библиотеки
begin
 if Addr(DllProc) = nil then             // Исли переменной DllProc не присвоено никакого значения тогда
  begin
   DllProc := Addr(DllMain);             // Присвоить переменной DllProc адрес процедуры DllMain
   DllMain(DLL_PROCESS_ATTACH);          // Выполнить процедуру DllMain с параметром DLL_PROCESS_ATTACH
  end;
end.
