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
  Proc      : array [1..8] of Procedure;   // массив типа Procedure
  FileName  : string;                      // Переменная для хранения полного имени файла
  APPDIR    : string;                      // Переменная для хранения пути к программе
  PARAMS    : string;                      // Переменная для хранения параметров
  ExeMain   : procedure;                   // Процедурная переменная для стартовой функции
  IniFile   : TextFile;                    // Переменная типа TextFile для файла настроек
  OSINFO    : TOSVersionInfo;

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

// Объявление списока экспортируемых функций
exports
  VerQueryValueW name 'VerQueryValueW',
  VerQueryValueA name 'VerQueryValueA',
  GetFileVersionInfoW name 'GetFileVersionInfoW',
  GetFileVersionInfoA name 'GetFileVersionInfoA',
  GetFileVersionInfoSizeW name 'GetFileVersionInfoSizeW',
  GetFileVersionInfoSizeA name 'GetFileVersionInfoSizeA',
  GetFileVersionInfoExW name 'GetFileVersionInfoExW',
  GetFileVersionInfoSizeExW name 'GetFileVersionInfoSizeExW';

// Удаления директорий
procedure DeleteDir(DirName: String);
var
  FileOp: TSHFileOpStruct;
begin
  FillChar(FileOp, SizeOf(FileOp), 0);                 // Очистить структуру от случайных данных
  FileOp.wFunc  := FO_DELETE;                          // Тип операции - удаление
  FileOp.fFlags := FOF_SILENT or FOF_NOCONFIRMATION;   // Флаги
  FileOp.pFrom  := PChar(DirName + #0);                // Имя и терминальный нуль для обозначения конца буфера
  SHFileOperation(FileOp);                             // Выполнить операцию
end;

// Удаление файлов и директорий по списку
procedure FDDELETE;
var
  I : Integer;
begin
  for i := 0 to FILELISTNUM - 1 do DeleteFile(PChar(FILELIST[i]));
  for i := 0 to DIRLISTNUM - 1 do DeleteDir(DIRLIST[i]);
end;

// Удаление файлов по списку
procedure FDELETE;
var
  i : integer;
begin
  for i := 0 to FILELISTNUM - 1 do DeleteFile(PChar(FILELIST[i]));
end;

// Функция для определения пути к программе
function GetAPPDir(APP : string): string;
var
  Len: INTEGER;
begin
  Len := Length(APP);
  while (Len <> 0) and (APP[Len] <> '\') do Dec(Len);
  Result := Copy(APP, 0, Len);
end;

// Функция для излечения значения параметра из строки
function GetParam(Param : string): string;
var
  Len    : INTEGER;
  SETPOS : INTEGER;
begin
  Len := Length(Param);
  SETPOS := POS('=', Param) + 1;
  Result := Copy(Param, SETPOS, Len - SETPOS + 1);
end;

// Функция для чтения параметра из ini файла
procedure READPARAM;
var
  IniLine : String;
  IniParam : String;
begin
  REGOFF := True;                               // Значение параметра по умолчанию
  AIDOFF := True;                               // Значение параметра по умолчанию
  DIROFF := False;                              // Значение параметра по умолчанию

  DIRLISTNUM := 0;
  FILELISTNUM := 0;

  // Чтение параметров из ини файла
  AssignFile(IniFile, APPDIR + 'Version.ini');  // Связать переменную IniFile с файлом Version.ini
  {$I-}                                         // Выключить контроль ошибок ввода-вывода
  Reset(IniFile);                               // Открыть файл для чтения
  {$I+}                                         // Включить контроль ошибок ввода-вывода
  if IOResult = 0 then begin                    // Если ошибок нет (файл отрыт) выполнить построчное чтение файла
  while (not EOF(IniFile)) do begin             // Пока не достигнут конец файла
    Readln(IniFile, IniLine);                   // Прочитат строку в переменную IniLine
    if POS(';', IniLine) = 0 then               // Если строка не комментарий
      begin
      IniParam := GetParam(IniLine);            // Извлечь из строки значение параметра
      if POS('REGOFF', IniLine) <> 0 then if IniParam = '1' then REGOFF := True else if IniParam = '0' then REGOFF := False;
      if POS('AIDOFF', IniLine) <> 0 then if IniParam = '1' then AIDOFF := True else if IniParam = '0' then AIDOFF := False;
      if POS('DIROFF', IniLine) <> 0 then if IniParam = '1' then DIROFF := True else if IniParam = '0' then DIROFF := False;
      // Заполнение массива из списка удаления директорий
      if POS('DeleteDir', IniLine) <> 0 then if IniParam <> '' then
      begin
      DIRLISTNUM := DIRLISTNUM + 1;
      SetLength(DIRLIST,DIRLISTNUM);
      DIRLIST[DIRLISTNUM-1] := IniParam;
      end;
      // Заполнение массива из списка удаления файлов
      if POS('DeleteFile', IniLine) <> 0 then if IniParam <> '' then
      begin
      FILELISTNUM := FILELISTNUM + 1;
      SetLength(FILELIST,FILELISTNUM);
      FILELIST[FILELISTNUM-1] := IniParam;
      end;
      end;
    end;
    CloseFile(IniFile);
  end;
end;

// Функция для добавления параметров запуска
function ADDParam(ARGS : string) : string;
var
  IniLine : String;
  IniParam : String;
  APP : String;
  ARGSSTART : STRING;
begin
  APPDIR := GetAPPDir(AppPatch);
  APP := APPDIR;
  ARGSSTART := '';
  // Проверка наличия параметра '--single-argument'
  if POS('--single-argument', ARGS) <> 0 then
  begin
    ARGSSTART := ARGS;
    ARGS := '';
  end;
  ARGS := ARGS + '--portable' + ' ';
  ARGS := ARGS + '--disable-features=RendererCodeIntegrity,FlashDeprecationWarning' + ' ';

  // Чтение параметров из ини файла
  AssignFile(IniFile, APPDIR + 'Version.ini');  // Связать переменную IniFile с файлом Version.ini
  {$I-}                                         // Выключить контроль ошибок ввода-вывода
  Reset(IniFile);                               // Открыть файл для чтения
  {$I+}                                         // Включить контроль ошибок ввода-вывода
  if IOResult = 0 then begin                    // Если ошибок нет (файл отрыт) выполнить построчное чтение файла
  while (not EOF(IniFile)) do begin             // Пока не достигнут конец файла
    Readln(IniFile, IniLine);                   // Прочитат строку в переменную IniLine
    if POS(';', IniLine) = 0 then               // Если строка не комментарий
      begin
      IniParam := GetParam(IniLine);            // Извлечь из строки значение параметра
      if POS('APPDIR', IniLine) <> 0 then if IniParam = '1' then APP := APPDIR else if IniParam = '0' then APP := '';
      if POS('DATADIR', IniLine) <> 0 then if IniParam <> '' then ARGS := ARGS + '--user-data-dir=' + '"' + APP + IniParam + '"' + ' ';
      if POS('CACHEDIR', IniLine) <> 0 then if IniParam <> '' then ARGS := ARGS + '--disk-cache-dir=' + '"' + APP + IniParam + '"' + ' ';
      if POS('RUNPARAM', IniLine) <> 0 then ARGS := ARGS + IniParam + ' ';
      end;
    end;
    CloseFile(IniFile);
  end;
  // Если параметры не заданы
  if (POS('--user-data-dir=', ARGS) = 0) then ARGS := ARGS + '--user-data-dir=' + '"' + APPDIR + 'User Data' + '"' + ' ';
  if (POS('--disk-cache-dir=', ARGS) = 0) then ARGS := ARGS + '--disk-cache-dir=' + '"' + APPDIR + 'Cache' + '"' + ' ';
  RESULT := ARGS + ARGSSTART;
end;

// Функция для определения версию ОС
procedure OSVER;
begin
  OSINFO.dwOSVersionInfoSize := SizeOf(OSINFO);
  GetVersionEx(OSINFO);
  if (OSINFO.dwMajorVersion = 5) and (OSINFO.dwMinorVersion = 1) then OS := 1;                                      // Windows XP 32
  if (OSINFO.dwMajorVersion = 5) and (OSINFO.dwMinorVersion = 2) then OS := 1;                                      // Windows XP 64
  if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 1) then OS := 2;                                      // Windows 7
  if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 2) then OS := 2;                                      // Windows 8
  if (OSINFO.dwMajorVersion = 6) and (OSINFO.dwMinorVersion = 3) then OS := 2;                                      // Windows 8.1
  if (OSINFO.dwMajorVersion = 10) and (OSINFO.dwMinorVersion = 0) and (OSINFO.dwBuildNumber < 22600) then OS := 2;  // Windows 10, первая версия Windows 11
  if (OSINFO.dwMajorVersion = 10) and (OSINFO.dwMinorVersion = 0) and (OSINFO.dwBuildNumber > 22600) then OS := 3;  // Windows 11
end;

procedure STARTPORTABLE(PARAM:string);
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
  if DIROFF = TRUE then FDDELETE;                                           // Удалить директории и файлы если параметр включен
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
  // Если в командной строке нет параметров -type= и --portable тогда выполнить процедуру STARTPORTABLE
  if (POS('-type=', ARG) = 0) and (POS('--portable', ARG) = 0) then STARTPORTABLE(ARG);
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
  ADDR(ExeMain) := ADDR(EPCODE);            // Назначить адрес процедуры ExeMain равным адресу структуры EPCODE
  HookPreferences;
  //HookLoader;                             // Перехват функции LdrLoadDll. Использовать для поиска и замены сигнатуры в памяти процесса.
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
  if OS > 1 then begin                                                     // Для ОС 7, 8, 10, 11
  Addr(proc[7]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoExW');     // Определить адрес функции
  Addr(proc[8]) := GetProcAddress(DLLHandle, 'GetFileVersionInfoSizeExW'); // Определить адрес функции
  end;
 end;

// Основная стартовая функция
procedure DllMain(fdwReason: DWORD);
begin
  if (fdwReason = DLL_PROCESS_ATTACH) then
  begin
    DisableThreadLibraryCalls(hInstance);                     // Отключить уведомления DLL_THREAD_ATTACH и DLL_THREAD_DETACH
    READPARAM;                                                // Прочитать параметры из INI файла
    OSVER;                                                    // Определить версию ОС
    RedirectEXP;                                              // Выполнить переадресацию функций экспорта
    RedirectEP;                                               // Выполнить переадресацию точки входа
  end;
  if DIROFF = TRUE then FDELETE;                              // Удалить файлы если параметр включен
end;

// Этот код выполняется каждый раз при загрузке библиотеки
begin
  if Addr(DllProc) = nil then                             // Если переменной DllProc не присвоено никакого значения тогда
  begin
    DllProc := Addr(DllMain);                             // Присвоить переменной DllProc адрес процедуры DllMain
    DllMain(DLL_PROCESS_ATTACH);                          // Выполнить процедуру DllMain с параметром DLL_PROCESS_ATTACH
  end;
end.
