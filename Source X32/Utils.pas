unit Utils;

interface

uses
  SysTypFunc;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}
{$WARN SYMBOL_PLATFORM OFF}

CONST
  faReadOnly  = $00000001 platform;
  faHidden    = $00000002 platform;
  faSysFile   = $00000004 platform;
  faVolumeID  = $00000008 platform deprecated;
  faDirectory = $00000010;
  faArchive   = $00000020 platform;
  faSymLink   = $00000040 platform;
  faAnyFile   = $0000003F;

TYPE
  TSearchRec = record
    Time: integer;
    Size: Int64;
    Attr: integer;
    Name: string;
    ExcludeAttr: integer;
    FindHandle: THandle  platform;
    FindData: TWin32FindData  platform;
  end;

var
  OS : Byte; // Переменная условного номера версии ОС  

procedure FindClose(var F: TSearchRec);
procedure Replace(var PSTR: string; RSTR: string);
procedure GetOSVer;
function FindFirst(const Path: string; Attr: Integer; var  F: TSearchRec): Integer;
function FindNext(var F: TSearchRec): Integer;
function XPOS(Const SubStr, Str : String) : Integer;
function FindMatchingFile(var F: TSearchRec): Integer;
function GetAPPDir(DIR : string): string;
function GetDIR(const PROGDIR: string; PROFDIR: string; FULLPATCH : boolean): string;
function DirNameDistil(const Dir : string): string;
function Upper(ch: AnsiChar): AnsiChar;
function Lower(ch: AnsiChar): AnsiChar;
function GetModule(Const Module: PChar): THandle;

implementation

// Функция для определения версию ОС
procedure GetOSVer;
var
  OSINFO : TOSVersionInfo;
begin
  OSINFO.dwOSVersionInfoSize := SizeOf(OSINFO);
  GetVersionEx(OSINFO);
  OS := 2;
  if OSINFO.dwMajorVersion = 5 then OS := 1; // Windows XP
end;

// Функция для получения идентификатора
function GetModule(Const Module: PChar): THandle;
begin
  Result := GetModuleHandle(Module);                       // Получить идентификатор
  if Result = 0 then Result := LoadLibrary(Module);        // Если идентификатор не получен загрузить библиотеку
end;

// Удалить из имени директории последовательно все '..\' и '.'
function DirNameDistil(const Dir : string): string;
var DirName : string;
begin
  DirName := Dir;
  while (XPOS('..\', DirName) <> 0) do DELETE(DirName, XPOS('..\', DirName), 3);
  while (XPOS('.\', DirName) <> 0) do DELETE(DirName, XPOS('.\', DirName), 1);
  Result := DirName;
end;

// Функция для извлечения пути к программе
function GetAPPDir(DIR : string): string;
var
  Len: INTEGER;
begin
  Len := Length(DIR);                                 // Определить длину записи пути
  while (Len <> 0) and (DIR[Len] <> '\') do Dec(Len); // Расчитать длину до первого символа '\' справа налево (отбрасывается имя файла)
  SetString(Result, PChar(DIR), Len);                 // Скопировать в результат сокращенный путь (с учетом символа '\')
end;

// Функция для получения пути к DATADIR и CACHEDIR
function GetDIR(const PROGDIR: string; PROFDIR: string; FULLPATCH : boolean): string;
var
  FName: PChar;
  Len: Integer;
  FileName: string;
  Buffer: array[0..MAX_PATH - 1] of Char;
begin
  Result := PROFDIR;
  if FULLPATCH = True then
  begin
    FileName:= PROGDIR + PROFDIR;
    Len := GetFullPathName(PChar(FileName), MAX_PATH, Buffer, FName);
    if Len <> 0 then SetString(Result, Buffer, Len)
  end;
end;

// Процедура для замены подстановочных строк
procedure REPLACE(var PSTR: string; RSTR: string);
var
  SETPOS : integer;
begin
  SETPOS := POS('%DATADIR%', PSTR); // Найти положение '%DATADIR%' в строке
  if SETPOS <> 0 then
  begin
    Delete(PSTR, SETPOS, 9);        // Удалить из строки '%DATADIR%' (9 символов)
    Insert(RSTR, PSTR, SETPOS);     // Вставить в строку
  end;
end;

// Перевод символов в верхний регистр
function Upper(ch: AnsiChar): AnsiChar;
begin
  if (ch in ['a'..'z']) then result := chr(ord(ch) - 32) else result := ch;
end;

// Перевод символов в нижний регистр
function Lower(ch: AnsiChar): AnsiChar;
begin
  if (ch in ['A'..'Z']) then result := chr(ord(ch) + 32) else result := ch;
end;

// -----------------------------------------------------
// Описание функций для поиска файлов и папок по шаблону
// -----------------------------------------------------
function FindMatchingFile(var F: TSearchRec): Integer;
begin
  with F do
  begin
    while FindData.dwFileAttributes and ExcludeAttr <> 0 do
      if not FindNextFile(FindHandle, FindData) then
      begin
        Result := GetLastError;
        Exit;
      end;
    Attr := FindData.dwFileAttributes;
    Name := FindData.cFileName;
  end;
  Result := 0;
end;

procedure FindClose(var F: TSearchRec);
begin
  if F.FindHandle <> INVALID_HANDLE_VALUE then
  begin
    SysTypFunc.FindClose(F.FindHandle);
    F.FindHandle := INVALID_HANDLE_VALUE;
  end;
end;

function FindFirst(const Path: string; Attr: Integer; var  F: TSearchRec): Integer;
const
  faSpecial = faHidden or faSysFile or faDirectory;
begin
  F.ExcludeAttr := not Attr and faSpecial;
  F.FindHandle := FindFirstFile(PChar(Path), F.FindData);
  if F.FindHandle <> INVALID_HANDLE_VALUE then
  begin
    Result := FindMatchingFile(F);
    if Result <> 0 then FindClose(F);
  end else
    Result := GetLastError;
end;

function FindNext(var F: TSearchRec): Integer;
begin
  if FindNextFile(F.FindHandle, F.FindData) then Result := FindMatchingFile(F) else Result := GetLastError;
end;

// -----------------------------------------------------------------
// Поиск позиции подстроки в строке не зависимо от регистра символов
// -----------------------------------------------------------------
function XPOS(Const SubStr, Str : String) : Integer;
var
  StrLen, SubStrLen : Integer;
  Compare : boolean;
  I, J : integer;
begin
  StrLen := Length(Str);
  SubStrLen := Length(SubStr);
  Result := 0;
  if SubStrLen = 0 then  Exit;
  if SubStrLen > StrLen then Exit;
  for I := 0 to StrLen - SubStrLen do                                // Цикл поиска подстроки
  begin
    Compare := True;                                                 // Начальное значение флага cовпадения
    for J := 1 to SubStrLen do                                       // Цикл посимвольного сравнения
    begin
      Compare := Upper(Str[J+I]) = Upper(SubStr[J]);                 // Привести символы к верхнему регистру и сравнить
      if Compare = False then break;                                 // Если флаг сброшен выйти из цикла
    end;
    if Compare = True then                                           // Если все символы совпали тогда
    begin
      Result := I + 1;
      break;
    end;
  end;
end;

end.