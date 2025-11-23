library version;

{$R 'VersionInfo.res' 'VersionInfo.rc'}

uses
  Windows,
  PSAPI,
  ShellAPI,
  Hook in 'Hook.pas',
  Portable in 'Portable.pas',
  Utils in 'Utils.pas',
  Refining in 'Refining.pas',
  Parametrs in 'Parametrs.pas';

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

var
  Proc      : array [1..8] of Procedure;   // массив типа Procedure
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
procedure DDelete;
var
  i : Integer;
  DirName : String;
  FileOp: TSHFileOpStruct;
begin
  FillChar(FileOp, SizeOf(FileOp), 0);                 // Очистить структуру от случайных данных
  FileOp.wFunc  := FO_DELETE;                          // Тип операции - удаление
  FileOp.fFlags := FOF_SILENT or FOF_NOCONFIRMATION;   // Флаги
  for i := 0 to DIRLISTNUM - 1 do
  begin
    DirName := DELDIRLIST[i];
    FileOp.pFrom  := PChar(DirName + #0);              // Имя и терминальный нуль для обозначения конца буфера
    SHFileOperation(FileOp);                           // Выполнить операцию
  end;
end;

// Удаление файлов по списку и шаблону
procedure FDelete;
var
  i : Integer;
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
      SetString(DirName, PChar(FILELIST[i]), Len);
      if FindFirst(FILELIST[i], faAnyFile, SearchResult) = 0 then // Найти файлы по шаблону из FILELIST[i]
        begin
          repeat DeleteFile(PChar(DirName + SearchResult.Name));  // Удалять найденные файлы
          until FindNext(SearchResult) <> 0;                      // до тех пор пока еще есть соответствующие шаблону файлы
          FindClose(SearchResult);                                // Освободить ресурсы используемые процессом поиска
        end;
    end;
  end;
end;

// Удаление файлов и директорий по списку
procedure FDDelete;
begin
  FDelete;
  DDelete;
end;

// Функция запуска браузера
procedure STARTPORTABLE(ARGS:string);
var
  ShellExecuteInfo: TShellExecuteInfo;     // Переменная для запуска через ShellExecuteEx
  StartupInfo: TStartupInfo;               // Переменная для запуска через CreateProcess
  ProcessInfo: TProcessInformation;        // Переменная для запуска через CreateProcess
begin
  // Получить полное именя файла с использованием API функции GetModuleFileName
  // Если вместо 0 вписать hInstance, то будет путь к имени DLL файла
  GetModuleFileName(0, AppPatch, SizeOF(AppPatch));
  FileName := AppPatch;
  ExeDir := GetAPPDir(AppPatch);
  PARAMS := ADDParam(ARGS);
  // MessageBox(0, pchar(PARAMS), 'Параметры перед запуском', MB_OK);       // Вывод окна перед запуском. Для отладки

  if STARTM = false then
  begin
    // Заполнение структуры для запуска программы
    FillChar(ShellExecuteInfo, SizeOf(TShellExecuteInfo), 0) ;                // Очистить структуру от случайных данных
    ShellExecuteInfo.cbSize := sizeof(TShellExecuteInfo);                     // Размер структуры в байтах
    ShellExecuteInfo.fMask := SEE_MASK_NOCLOSEPROCESS or SEE_MASK_FLAG_NO_UI; // Комбинация флагов, определяющих используемую часть структуры
    ShellExecuteInfo.lpVerb := 'open';                                        // Строка, определяющее действие с файлом. 'open' запускает исполняемый файл
    ShellExecuteInfo.lpFile := pchar(FileName);                               // Имя файла (полный путь к файлу)
    ShellExecuteInfo.lpDirectory := pchar(ExeDir);                            // Рабочая директория программы
    ShellExecuteInfo.nShow := SW_SHOWNORMAL;                                  // Способ отображения окна
    ShellExecuteInfo.lpParameters := pchar(PARAMS);                           // Параметры
    if ShellExecuteEx(ADDR(ShellExecuteInfo)) then ExitProcess(0);            // Запустить программу
  end
  else begin
    FillChar(StartupInfo, SizeOf(StartupInfo), 0);
    StartupInfo.cb := SizeOf(StartupInfo);
    if CreateProcess(nil, pchar(FileName + ' ' + PARAMS), nil, nil, false, 0, nil, pchar(ExeDir), StartupInfo, ProcessInfo) then
    begin
      ExitProcess(0);
    end;
  end;
end;

// Определить параметры коммандной строки и запустить программу
procedure REDIRECT;
var
  ARG: String;
  i: integer;
begin
  i := 2;
  ARG := '';
  ARG := GetCommandLine;                  // Получить полную командную строку

  // Первый параметр - это выполняемая программа, он всегда передаётся в кавычках. Следующие это остальные параметры.
  // Первый параметр нужно исключить.
  if ARG[1] = '"' then                    // Если в начале кавычка тогда
  begin
    while (ARG[I] <> '"') do inc(I);      // дойти до второй кавычки
    if (ARG[I] = '"') then inc(I);        // если кавычка то перейти за неё
    if (ARG[I] = ' ') then inc(I);        // если пробел то перейти за него
    Delete(ARG, 1, I-1);                  // Исключить первый параметр
  end;
  if ARG <> '' then ARG := ARG + ' ';     // Добавить пробел (пробел - это разделитель между параметрами)

  if DIROFF = true then FDDELETE;         // Удалить директории и файлы если параметр включен
  // Если в командной строке нет параметров -type= и --portable тогда выполнить процедуру STARTPORTABLE
  if (POS('-type=', ARG) = 0) and (POS('--portable', ARG) = 0) then STARTPORTABLE(ARG);
  SetHook(OEPCODE, 0); // Отключить перехват точки входа
  ExeMain;             // Выполнить процедуру ExeMain
end;

// Определение и подмена адреса точки входа
procedure RedirectEP;
var
  MI   : MODULEINFO;    // Переменная типа MODULEINFO, MODULEINFO - это структура, которая содержит поле EntryPoint
  EntryADDR : PBYTE;    // Переменная указатель на адреса точки входа
begin
  HookPreferences;
  GetModuleInformation(GetCurrentProcess, GetModuleHandle(NIL), Addr(MI), sizeof(MODULEINFO)); // Считать информацию о процессе
  EntryADDR := MI.EntryPoint;               // Считать в переменную адрес точки входа из поля EntryPoint структуры MI
  CodeHook(EntryADDR, ADDR(REDIRECT), 1);   // Подмена адреса точки входа на адрес функции из прокси библиотеки
  ADDR(ExeMain) := EntryADDR;               // Назначить адрес процедуры ExeMain равным адресу точки входа
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
    // DisableThreadLibraryCalls(hInstance);                  // Отключить уведомления DLL_THREAD_ATTACH и DLL_THREAD_DETACH
    READPARAM;                                                // Прочитать параметры из INI файла
    GetOSVer;                                                 // Определить версию ОС
    RedirectEXP;                                              // Выполнить переадресацию функций экспорта
    RedirectEP;                                               // Выполнить переадресацию точки входа
  end;
  if (fdwReason = DLL_PROCESS_DETACH) then
  begin
    if DIROFF = TRUE then FDELETE;                            // Удалить файлы если параметр включен
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