library version;

{$R 'VersionInfo.res' 'VersionInfo.rc'}

uses
  Windows,
  Hook in 'Hook.pas',
  Portable in 'Portable.pas',
  Utils in 'Utils.pas',
  Refining in 'Refining.pas',
  Parametrs in 'Parametrs.pas';

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

var
  Proc : array [1..8] of Procedure;        // массив типа Procedure

// Описание функций для метода dll wraper
// Функции представляют собой джампы на адреса функций системного файла version.dll.
// Адреса функций определяются динамически.

procedure GetFileVersionInfoSizeW; stdcall; asm jmp QWORD ptr [proc + 0 * 8] end;
procedure GetFileVersionInfoW; stdcall; asm jmp QWORD ptr [proc + 1 * 8] end;
procedure VerQueryValueW; stdcall; asm jmp QWORD ptr [proc + 2 * 8] end;
procedure GetFileVersionInfoSizeA; stdcall; asm jmp QWORD ptr [proc + 3 * 8] end;
procedure GetFileVersionInfoA; stdcall; asm jmp QWORD ptr [proc + 4 * 8] end;
procedure VerQueryValueA; stdcall; asm jmp QWORD ptr [proc + 5 * 8] end;
procedure GetFileVersionInfoExW; stdcall; asm jmp QWORD ptr [proc + 6 * 4] end;
procedure GetFileVersionInfoSizeExW; stdcall; asm jmp QWORD ptr [proc + 7 * 4] end;

// Объявление списка экспортируемых функций
exports
  VerQueryValueW name 'VerQueryValueW',
  VerQueryValueA name 'VerQueryValueA', 
  GetFileVersionInfoW name 'GetFileVersionInfoW', 
  GetFileVersionInfoA name 'GetFileVersionInfoA',
  GetFileVersionInfoSizeW name 'GetFileVersionInfoSizeW',  
  GetFileVersionInfoSizeA name 'GetFileVersionInfoSizeA',
  GetFileVersionInfoExW name 'GetFileVersionInfoExW',
  GetFileVersionInfoSizeExW name 'GetFileVersionInfoSizeExW';

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
  if OS > 1 then begin                                                     // Для ОС 7, 8, 10, 11
  Addr(proc[7]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoExW');     // Определить адрес функции
  Addr(proc[8]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoSizeExW'); // Определить адрес функции
  end;
end;

// Основная стартовая функция
procedure DllMain(fdwReason: DWORD);
begin
  if (fdwReason = DLL_PROCESS_ATTACH) then                // Если подключение библиотеки
  begin
    READPARAM;                                            // Прочитать параметры из INI файла
    GetOSVer;                                             // Определить версию ОС
    RedirectEXP;                                          // Выполнить переадресацию функций экспорта
    HookPreferences;                                      // Выполнить переадресацию функций
    if DIROFF = TRUE then FDDELETE;                       // Удалить файлы и директории если параметр включен
  end;
  if (fdwReason = DLL_PROCESS_DETACH) then                // Если отключение библиотеки
  begin
    if DIROFF = TRUE then FDELETE;                        // Удалить файлы если параметр включен
  end;
end;

// Этот код выполняется каждый раз при обращении к точке входа библиотеки
begin
  if Addr(DllProc) = nil then                             // Если переменной DllProc не присвоено никакого значения тогда
  begin
    DllProc := Addr(DllMain);                             // Присвоить переменной DllProc адрес процедуры DllMain
    DllProc(DLL_PROCESS_ATTACH);                          // Выполнить процедуру DllMain с параметром DLL_PROCESS_ATTACH
  end;
end.