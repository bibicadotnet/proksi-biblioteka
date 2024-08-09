library version;

uses
  Windows,
  PSAPI,
  ShellAPI,
  Hook in 'Hook.pas',
  Portable in 'Portable.pas',
  Utils in 'Utils.pas';
  
{$R version.res}

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

VAR
  AppPatch  : array [0..MAX_PATH] of Char;
  Proc      : array [1..8] of Procedure;   // массив типа Procedure
  FileName  : string;                      // Переменная для хранения полного имени файла
  APPDIR    : string;                      // Переменная для хранения пути к программе
  PARAMS    : string;                      // Переменная для хранения параметров запуска
  ExeMain   : procedure;                   // Процедурная переменная для стартовой функции
  IniFile   : TextFile;                    // Переменная типа TextFile для файла настроек
  OSINFO    : TOSVersionInfo;

  FULLPATCH : boolean;
  DATADIR   : string;
  CACHEDIR  : string;
  RUNPARAM  : string;

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

// Функция удаления директорий
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

// Удаление файлов по списку и шаблону
procedure FDELETE;
var
  i : INTEGER;
  DirName : String;
  Len: INTEGER;
  SearchResult : TSearchRec;
begin
  for i := 0 to FILELISTNUM - 1 do
  begin
  if XPOS('*', FILELIST[i]) = 0 then DeleteFile(PChar(FILELIST[i]));
  if XPOS('*', FILELIST[i]) <> 0 then
    begin
      DirName := '';
      // Извлечь путь к файлу
      Len := Length(FILELIST[i]);
      while (Len <> 0) and (FILELIST[i][Len] <> '\') do Dec(Len);
      DirName := Copy(FILELIST[i], 0, Len);
      // Найти и удалить файлы по шаблону
      if FindFirst(FILELIST[i], faAnyFile, SearchResult) = 0 then
        begin
          repeat
            DeleteFile(PChar(DirName + SearchResult.Name));
          until FindNext(SearchResult) <> 0;
          FindClose(SearchResult);
        end;
    end;
  end;
end;

// Удаление файлов и директорий по списку
procedure FDDELETE;
var
  I : Integer;
begin
  FDELETE;
  for i := 0 to DIRLISTNUM - 1 do DeleteDir(DELDIRLIST[i]);
end;

// Функция для определения пути к программе
function GetAPPDir(DIR : string): string;
var
  Len: INTEGER;
begin
  Len := Length(DIR);
  while (Len <> 0) and (DIR[Len] <> '\') do Dec(Len);
  Result := Copy(DIR, 0, Len);
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
  RMDISK := False;                              // Значение параметра по умолчанию
  FULLPATCH := True;                            // Значение параметра по умолчанию

  DATADIR   := '';
  CACHEDIR  := '';
  RUNPARAM  := '';

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
      if POS('REGOFF=', IniLine) <> 0 then if IniParam = '1' then REGOFF := True else if IniParam = '0' then REGOFF := False;
      if POS('AIDOFF=', IniLine) <> 0 then if IniParam = '1' then AIDOFF := True else if IniParam = '0' then AIDOFF := False;
      if POS('DIROFF=', IniLine) <> 0 then if IniParam = '1' then DIROFF := True else if IniParam = '0' then DIROFF := False;
      if POS('RMDISK=', IniLine) <> 0 then if IniParam = '1' then RMDISK := True else if IniParam = '0' then RMDISK := False;

      if POS('APPDIR=', IniLine) <> 0 then if IniParam = '0' then FULLPATCH := False else if IniParam = '1' then FULLPATCH := True;
      if POS('DATADIR=', IniLine) <> 0 then if IniParam <> '' then DATADIR := IniParam;
      if POS('CACHEDIR=', IniLine) <> 0 then if IniParam <> '' then CACHEDIR := IniParam;
      if POS('RUNPARAM=', IniLine) <> 0 then if IniParam <> '' then RUNPARAM := IniParam;

      // Заполнение массивов из списка удаления директорий
      if POS('DeleteDir', IniLine) <> 0 then if IniParam <> '' then
        begin
        if DATADIR <> '' then REPLACE(IniParam, DATADIR);
        DIRLISTNUM := DIRLISTNUM + 1;
        SetLength(DELDIRLIST,DIRLISTNUM);
        SetLength(BLOCKDIRLIST,DIRLISTNUM);
        DELDIRLIST[DIRLISTNUM-1] := IniParam;
        BLOCKDIRLIST[DIRLISTNUM-1] := DirNameDistil(IniParam);
        end;
      // Заполнение массива из списка удаления файлов
      if POS('DeleteFile', IniLine) <> 0 then if IniParam <> '' then
        begin
        if DATADIR <> '' then REPLACE(IniParam, DATADIR);  // Заменить %DATADIR% на значение из параметра DATADIR
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
  ARGSSTART : String;

  USERDATADIR    : String;
  DISKCACHEDIR   : String;

begin
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

  //if (POS('--disk-cache-dir=', ARGS) = 0) then ARGS := ARGS + '--disk-cache-dir=' + '"' + 'nul' + '"' + ' ';
  //if (POS('--disk-cache-size=', ARGS) = 0) then ARGS := ARGS + '--disk-cache-size=' + '"' + '0' + '"' + ' ';
  //if (POS('--media-cache-size=', ARGS) = 0) then ARGS := ARGS + '--media-cache-size=' + '"' + '0' + '"' + ' ';
  //ARGS := ARGS + '--simulate-critical-update' + ' ';
  //ARGS := ARGS + '--disable-logging' + ' ';
  //ARGS := ARGS + '--no-first-run' + ' ';
  //ARGS := ARGS + '--no-sandbox' + ' ';
  //ARGS := ARGS + '--test-type' + ' ';
  //ARGS := ARGS + '--ppapi-flash-path=' + '"' + APPDIR + 'plugins\pepflashplayer32.dll' + ' ';

  if FULLPATCH = FALSE then APP := '';
  if DATADIR <> '' then USERDATADIR := GETUSERDATADIR(APP, DATADIR);
  if CACHEDIR <> '' then DISKCACHEDIR := GETDISKCACHEDIR(APP, CACHEDIR);

  if DATADIR <> '' then ARGS := ARGS + '--user-data-dir=' + '"' + USERDATADIR + '"' + ' ';
  if CACHEDIR <> '' then ARGS := ARGS + '--disk-cache-dir=' + '"' + DISKCACHEDIR + '"' + ' ';
  if RUNPARAM <> '' then ARGS := ARGS + RUNPARAM + ' ';

  // Если параметры не заданы
  if POS('--user-data-dir=', ARGS) = 0 then ARGS := ARGS + '--user-data-dir=' + '"' + APPDIR + 'User Data' + '"' + ' ';
  if POS('--disk-cache-dir=', ARGS) = 0 then ARGS := ARGS + '--disk-cache-dir=' + '"' + APPDIR + 'Cache' + '"' + ' ';
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

procedure STARTPORTABLE(ARGS:string);
var
  ShellExecuteInfo: TShellExecuteInfo;
begin
  // Получить полное именя файла с использованием API функции GetModuleFileName
  // Если вместо 0 вписать hInstance, то будет путь к имени DLL файла
  GetModuleFileName(0, AppPatch, SizeOF(AppPatch));
  FileName := AppPatch;

  APPDIR := GetAPPDir(AppPatch);
  PARAMS := ADDParam(ARGS);
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