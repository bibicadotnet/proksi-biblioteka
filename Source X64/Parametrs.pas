unit Parametrs;

interface

uses
  Windows,
  Utils;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type

  // Запись для хранения имен доменов к которым обнуляются запросы
  TDomainList = record
    len : byte;
    buf : array of AnsiChar;
  end;

var
  AppPatch  : array [0..MAX_PATH] of Char; // Переменная для хранения полного пути к программе
  FileName  : string;                      // Переменная для хранения полного имени файла
  APPDIR    : string;                      // Переменная для хранения пути к директории программы
  PARAMS    : string;                      // Переменная для хранения параметров запуска
  IniFile   : TextFile;                    // Переменная типа TextFile для файла настроек

  FULLPATCH : boolean;
  DATADIR   : string;
  CACHEDIR  : string;
  RUNPARAM  : string;

  REGOFF : boolean;          // Переменная для отключения записи в реестр
  AIDOFF : boolean;          // Переменная для отключения идентификации приложения
  DIROFF : boolean;          // Переменная для отключения создания папок
  RMDISK : boolean;          // Переменная для включения определения пути к TEMP на рамдиске
  REFINE : boolean;          // Переменная для включения обнуления запросов к серверам
  SPFOLD : boolean;          // Переменная для включения подмены пути к спецпапкам
  STARTM : boolean;          // Переменная для выбора метода запуска
  BCTOFF : boolean;          // Переменная для отключения широковещательных рассылок
  ECHOFF : boolean;          // Переменная для отключения ECH и DoH

  FILELIST     : array of String;  // Массив списка файлов
  DELDIRLIST   : array of String;  // Массив списка директорий для удаления
  BLOCKDIRLIST : array of String;  // Массив списка директорий для блокировки
  DIRLISTNUM   : integer;          // Число эдементов массива списка директорий
  FILELISTNUM  : integer;          // Число эдементов массива списка файлов

  SPECFOLDER : string;
  COMPNAME   : string;

  REFINELIST : array of TDomainList;  // Массив записей для обнуления запросов к гугле и его доменам
  REFINELISTNUM : integer;            // Число эдементов массива списка обнуления

procedure READPARAM;
function ADDParam(ARGS : string) : string;

implementation

// Функция для замены расширения файла в полном пити
function GetIniName(DIR : string): string;
var
  Len: INTEGER;
begin
  Len := Length(DIR);
  while (Len <> 0) and (DIR[Len] <> '.') do Dec(Len);
  Result := Copy(DIR, 0, Len) + 'ini';
end;

// Функция для излечения значения параметра из строки
function GetParam(IniLine : string; var IniParam : string): boolean;
var
  Len    : INTEGER;
  SETPOS : INTEGER;
begin
  Result := False;
  Len := Length(IniLine);
  if Len = 0 then exit;
  SETPOS := POS('=', IniLine) + 1;
  IniParam := Copy(IniLine, SETPOS, Len - SETPOS + 1);
  if (POS(';', IniLine) = 0) or (POS(';', IniLine) > 2) then Result := True; // Если строка не комментарий
  if IniParam = '' then Result := False;
end;

// Функция для добавления параметров запуска
function ADDParam(ARGS : string) : string;
var
  APP : String;
  ARGSSTART : String;
  USERDATADIR    : String;
  DISKCACHEDIR   : String;

begin
  APP := ExeDir;
  ARGSSTART := '';
  // Проверка наличия параметра '--single-argument'
  if POS('--single-argument', ARGS) <> 0 then
  begin
    ARGSSTART := ARGS;
    ARGS := '';
  end;

  ARGS := ARGS + '--portable' + ' ';
  ARGS := ARGS + '--disable-features=RendererCodeIntegrity,FlashDeprecationWarning' + ' ';

  if FULLPATCH = FALSE then APP := '';
  if DATADIR <> '' then USERDATADIR := GETDIR(APP, DATADIR);
  if CACHEDIR <> '' then DISKCACHEDIR := GETDIR(APP, CACHEDIR);

  if DATADIR <> '' then ARGS := ARGS + '--user-data-dir=' + '"' + USERDATADIR + '"' + ' ';
  if CACHEDIR <> '' then ARGS := ARGS + '--disk-cache-dir=' + '"' + DISKCACHEDIR + '"' + ' ';
  if RUNPARAM <> '' then ARGS := ARGS + RUNPARAM + ' ';

  // Если параметры не заданы
  if POS('--user-data-dir=', ARGS) = 0 then ARGS := ARGS + '--user-data-dir=' + '"' + ExeDir + 'User Data' + '"' + ' ';
  if POS('--disk-cache-dir=', ARGS) = 0 then ARGS := ARGS + '--disk-cache-dir=' + '"' + ExeDir + 'Cache' + '"' + ' ';
  RESULT := ARGS + ARGSSTART;
end;

// Функция для чтения параметра из ini файла
procedure READPARAM;
var
  IniName : String;
  IniLine : String;
  IniParam : String;
  I : integer;
begin
  REGOFF := True;                               // Значение параметра по умолчанию
  AIDOFF := True;                               // Значение параметра по умолчанию
  DIROFF := False;                              // Значение параметра по умолчанию
  RMDISK := False;                              // Значение параметра по умолчанию
  REFINE := True;                               // Значение параметра по умолчанию
  SPFOLD := False;                              // Значение параметра по умолчанию
  BCTOFF := True;                               // Значение параметра по умолчанию
  STARTM := False;                              // Значение параметра по умолчанию
  ECHOFF := False;                              // Значение параметра по умолчанию
  FULLPATCH := True;                            // Значение параметра по умолчанию

  DATADIR   := '';
  CACHEDIR  := '';
  RUNPARAM  := '';
  SPECFOLDER := '';
  COMPNAME   := '';

  DIRLISTNUM := 0;
  FILELISTNUM := 0;
  REFINELISTNUM := 0;

  GetModuleFileName(HInstance, AppPatch, SizeOF(AppPatch));  // Определить путь к dll
  IniName := GetIniName(AppPatch);                           // Получить путь к ini файлу

  // Чтение параметров из ини файла
  AssignFile(IniFile, IniName);                 // Связать переменную IniFile с файлом ini
  {$I-}                                         // Выключить контроль ошибок ввода-вывода
  Reset(IniFile);                               // Открыть файл для чтения
  {$I+}                                         // Включить контроль ошибок ввода-вывода
  if IOResult = 0 then begin                    // Если ошибок нет (файл отрыт) выполнить построчное чтение файла
  while (not EOF(IniFile)) do begin             // Пока не достигнут конец файла
    Readln(IniFile, IniLine);                   // Прочитат строку в переменную IniLine
    if GetParam(IniLine, IniParam) = true then  // Извлечь из строки значение параметра
    begin
      if POS('REGOFF=', IniLine) <> 0 then if IniParam = '1' then REGOFF := True else if IniParam = '0' then REGOFF := False;
      if POS('AIDOFF=', IniLine) <> 0 then if IniParam = '1' then AIDOFF := True else if IniParam = '0' then AIDOFF := False;
      if POS('DIROFF=', IniLine) <> 0 then if IniParam = '1' then DIROFF := True else if IniParam = '0' then DIROFF := False;
      if POS('RMDISK=', IniLine) <> 0 then if IniParam = '1' then RMDISK := True else if IniParam = '0' then RMDISK := False;
      if POS('REFINE=', IniLine) <> 0 then if IniParam = '1' then REFINE := True else if IniParam = '0' then REFINE := False;
      if POS('SPFOLD=', IniLine) <> 0 then if IniParam = '1' then SPFOLD := True else if IniParam = '0' then SPFOLD := False;
      if POS('BCTOFF=', IniLine) <> 0 then if IniParam = '1' then BCTOFF := True else if IniParam = '0' then BCTOFF := False;
      if POS('STARTM=', IniLine) <> 0 then if IniParam = '1' then STARTM := True else if IniParam = '0' then STARTM := False;
      if POS('ECHOFF=', IniLine) <> 0 then if IniParam = '1' then ECHOFF := True else if IniParam = '0' then ECHOFF := False;

      if POS('APPDIR=', IniLine) <> 0 then if IniParam = '0' then FULLPATCH := False else if IniParam = '1' then FULLPATCH := True;
      if POS('DATADIR=', IniLine) <> 0 then if IniParam <> '' then DATADIR := IniParam;
      if POS('CACHEDIR=', IniLine) <> 0 then if IniParam <> '' then CACHEDIR := IniParam;
      if POS('SPECFOLDER=', IniLine) <> 0 then if IniParam <> '' then SPECFOLDER := IniParam;
      if POS('RUNPARAM=', IniLine) <> 0 then if IniParam <> '' then RUNPARAM := IniParam;
      if POS('COMPNAME=', IniLine) <> 0 then if IniParam <> '' then COMPNAME := IniParam;

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

      // Заполнить массив записей из списка обнуления запросов к гугло и его доменам
      if POS('NullDomain', IniLine) <> 0 then if IniParam <> '' then
      begin
        REFINELISTNUM := REFINELISTNUM + 1;
        SetLength(REFINELIST, REFINELISTNUM);
        REFINELIST[REFINELISTNUM-1].len := Length(IniParam);
        SetLength(REFINELIST[REFINELISTNUM-1].buf, REFINELIST[REFINELISTNUM-1].len + 1);  // + 1 к размеру для добавления элемента с #0
        for I := 0 to REFINELIST[REFINELISTNUM-1].len - 1 do REFINELIST[REFINELISTNUM-1].buf[I] := AnsiChar(IniParam[I + 1]);
      end;

      end;
    end;
    CloseFile(IniFile);
  end;
end;

end.
