library version;

uses
  Windows,
  PSAPI,
  ShellAPI,
  Hook in 'Hook.pas',
  Portable in 'Portable.pas';

{$R version.res}
{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}
VAR
  AppPatch  : array [0..MAX_PATH] of Char;
  Proc : array [1..8] of Procedure;        // массив типа Procedure
  FileName  : string;                      // Переменная для хранения полного имени файла
  APPDIR    : string;                      // Переменная для хранения пути к программе
  PARAMS    : string;                      // Переменная для хранения параметров
  ExeMain   : procedure;                   // Процедурная переменная для стартовой функции

// Описание функций для метода dll wraper
// Функции представляют собой джампы на адреса функций системного файла version.dll.
// Адреса функций определяются динамически.

procedure GetFileVersionInfoSizeW; stdcall; asm jmp dword ptr [proc + 0 * 4] end;
procedure GetFileVersionInfoW; stdcall; asm jmp dword ptr [proc + 1 * 4]; end;
procedure VerQueryValueW; stdcall; asm jmp dword ptr [proc + 2 * 4]; end;
procedure GetFileVersionInfoSizeA; stdcall; asm jmp dword ptr [proc + 3 * 4]; end;
procedure GetFileVersionInfoA; stdcall; asm jmp dword ptr [proc + 4 * 4]; end;
procedure VerQueryValueA; stdcall; asm jmp dword ptr [proc + 5 * 4]; end;
procedure GetFileVersionInfoExW; stdcall; asm jmp dword ptr [proc + 6 * 4]; end;
procedure GetFileVersionInfoSizeExW; stdcall; asm jmp dword ptr [proc + 7 * 4]; end;

{
function GetFileVersionInfoSizeW(lptstrFilename: LPCWSTR; var lpdwHandle: DWORD):DWORD; stdcall; begin proc[1] end;
function GetFileVersionInfoW(lptstrFilename: LPCWSTR; dwHandle: DWORD; dwLen: DWORD; lpData: Pointer):BOOL; stdcall; begin proc[2] end;
function VerQueryValueW(pBlock: Pointer; lpSubBlock: LPWSTR; var lplpBuffer: Pointer;  var puLen: UINT):BOOL; stdcall; begin proc[3] end;
function GetFileVersionInfoSizeA(lptstrFilename: LPCSTR; var lpdwHandle: DWORD):DWORD; stdcall; begin proc[4] end;
function GetFileVersionInfoA(lptstrFilename: LPCSTR; dwHandle: DWORD; dwLen: DWORD; lpData: Pointer):BOOL; stdcall; begin proc[5] end;
function VerQueryValueA(pBlock: Pointer; lpSubBlock: LPSTR; var lplpBuffer: Pointer; var puLen: UINT):BOOL; stdcall; begin proc[6] end;
procedure GetFileVersionInfoExW; begin proc[7] end;
procedure GetFileVersionInfoSizeExW; begin proc[8] end;
}

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
  //if (POS('--disk-cache-dir=', ARGS) = 0) then ARGS := ARGS + '--disk-cache-dir=' + '"' + 'nul' + '"' + ' ';
  //if (POS('--disk-cache-size=', ARGS) = 0) then ARGS := ARGS + '--disk-cache-size=' + '"' + '0' + '"' + ' ';
  //if (POS('--media-cache-size=', ARGS) = 0) then ARGS := ARGS + '--media-cache-size=' + '"' + '0' + '"' + ' ';
  ARGS := ARGS + '--disable-logging' + ' ';
  //ARGS := ARGS + '--no-first-run' + ' ';
  //ARGS := ARGS + '--ppapi-flash-path=' + '"' + APPDIR + 'plugins\pepflashplayer32.dll' + ' ';
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
begin
  GetModuleInformation(GetCurrentProcess, GetModuleHandle(NIL), Addr(MI), sizeof(MODULEINFO)); // Считать информацию о процессе
  EntryADDR := MI.EntryPoint;               // Считать в переменную адрес точки входа из поля EntryPoint структуры MI
  CodeHook(EntryADDR, ADDR(REDIRECT), 1);   // Подмена адреса точки входа в процессе на адрес функции из DLL.
  ADDR(ExeMain) := ADDR(EPCODE);            // Назначить адрес процедуры ExeMain равным адресу структуры OLDCODE
  //HookPreferences;
  //HookLoader;
end;

// Обертка для переадресации экспортируемых функций
procedure RedirectEXP;
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
    DisableThreadLibraryCalls(hInstance);                     // Отключить уведомления DLL_THREAD_ATTACH и DLL_THREAD_DETACH
    // Макстон Браве Хромиум Цент
    HMODULE := GetModuleHandle('chrome_elf.dll');             // HMODULE = дескриптор модуля (адрес по которому он загружен)
    if (HMODULE <> 0) and (BLOK1 = FALSE) then REGBLOCKER(1); // Если модуль загружен выполнить процедуру REGBLOCKER
    // Вивальди
    HMODULE := GetModuleHandle('vivaldi_elf.dll');            // HMODULE = дескриптор модуля (адрес по которому он загружен)
    if (HMODULE <> 0) and (BLOK1 = FALSE) then REGBLOCKER(1); // Если модуль загружен выполнить процедуру REGBLOCKER
    // Яндекс
    HMODULE := GetModuleHandle('browser_elf.dll');            // HMODULE = дескриптор модуля (адрес по которому он загружен)
    if (HMODULE <> 0) and (BLOK1 = FALSE) then REGBLOCKER(1); // Если модуль загружен выполнить процедуру REGBLOCKER
    // Опера
    HMODULE := GetModuleHandle('opera_elf.dll');              // HMODULE = дескриптор модуля (адрес по которому он загружен)
    if (HMODULE <> 0) and (BLOK1 = FALSE) then REGBLOCKER(1); // Если модуль загружен выполнить процедуру REGBLOCKER
    RedirectEXP;                                              // Шаг 1. Выполнить переадресацию функций экспорта
    RedirectEP;                                               // Шаг 2. Выполнить переадресацию точки входа
  end;
end;

// Этот код выполняется каждый раз при при загрузке библиотеки
begin
  if Addr(DllProc) = nil then                             // Исли переменной DllProc не присвоено никакого значения тогда
  begin
    DllProc := Addr(DllMain);                             // Присвоить переменной DllProc адрес процедуры DllMain
    DllMain(DLL_PROCESS_ATTACH);                          // Выполнить процедуру DllMain с параметром DLL_PROCESS_ATTACH
  end;
end.
