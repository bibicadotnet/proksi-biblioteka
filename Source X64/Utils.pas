unit Utils;

interface

uses
  Windows;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}
{$WARN SYMBOL_PLATFORM OFF}
{$WARN SYMBOL_DEPRECATED OFF}

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
    Time: integer platform deprecated;
    Size: Int64;
    Attr: integer;
    Name: string;
    ExcludeAttr: integer;
    FindHandle: THandle platform;
    FindData: TWin32FindData platform;
  end;

var
  OS : byte; // Переменная условного номера версии ОС  

procedure FindClose(var F: TSearchRec);
procedure REPLACE(var PSTR: string; RSTR: string);
procedure GetOSVer;
function FindFirst(const Path: string; Attr: Integer; var  F: TSearchRec): Integer;
function FindNext(var F: TSearchRec): Integer;
function XPOS(Const SubStr, Str : String) : Integer;
function FindMatchingFile(var F: TSearchRec): Integer;
function GetDir(const APPDIR: string; PROFDIR : string): string;
function DirNameDistil(const Dir : string): string;

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

// Удалить из имени директории последовательно все '..\' и '.'
function DirNameDistil(const Dir : string): string;
var DirName : string;
begin
  DirName := Dir;
  while (XPOS('..\', DirName) <> 0) do DELETE(DirName, XPOS('..\', DirName), 3);
  while (XPOS('.\', DirName) <> 0) do DELETE(DirName, XPOS('.\', DirName), 1);
  Result := DirName;
end;

// Функция для формирования пути к DATADIR и CACHEDIR
function GetDIR(const APPDIR: string; PROFDIR : string): string;
var
  Len : integer;
begin
  Len := Length(APPDIR);
  while (POS('..\', PROFDIR) <> 0) and (Len > 2) do
    begin
      if (APPDIR[Len] = '\') then Dec(Len);
      while (Len <> 0) and (APPDIR[Len] <> '\') do Dec(Len);
      Delete(PROFDIR, POS('..\', PROFDIR), 3);
    end;
  Result := Copy(APPDIR, 0, Len);
  Result := Result +  PROFDIR;
end;

// Процедура для замены подстановочных строк
procedure Replace(var PSTR: string; RSTR: string);
var
  SETPOS : integer;
begin
  SETPOS := POS('%DATADIR%', PSTR);
  if SETPOS <> 0 then
  begin
    Delete(PSTR, SETPOS, 9);
    Insert(RSTR, PSTR, SETPOS);
  end;
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
    Windows.FindClose(F.FindHandle);
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

// Поиск позиции подстроки в строке не зависимо от регистра символов
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
      Compare := UpCase(Str[J+I]) = UpCase(SubStr[J]);               // Привести символы к верхнему регистру и сравнить
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