unit Utils;

interface

uses
  Windows;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}
{$WARN SYMBOL_PLATFORM OFF}
{$WARN SYMBOL_DEPRECATED OFF}

TYPE
  TFileName = type string;

  TSearchRec = record
    Time: Integer platform deprecated;
    Size: Int64;
    Attr: Integer;
    Name: TFileName;
    ExcludeAttr: Integer;
    FindHandle: THandle platform;
    FindData: TWin32FindData platform;
  end;

  LongRec = packed record
    case Integer of
      0: (Lo, Hi: Word);
      1: (Words: array [0..1] of Word);
      2: (Bytes: array [0..3] of Byte);
  end;

function FindMatchingFile(var F: TSearchRec): Integer;
procedure FindClose(var F: TSearchRec);
function FindFirst(const Path: string; Attr: Integer; var  F: TSearchRec): Integer;
function FindNext(var F: TSearchRec): Integer;
function XPOS(Const SubStr, Str : String) : Integer;

CONST

  faReadOnly  = $00000001 platform;
  faHidden    = $00000002 platform;
  faSysFile   = $00000004 platform;
  faVolumeID  = $00000008 platform deprecated;
  faDirectory = $00000010;
  faArchive   = $00000020 platform;
  faSymLink   = $00000040 platform;
  faAnyFile   = $0000003F;

implementation

// -----------------------------------------------------
// Описание функций для поиска файлов и папок по шаблону
// -----------------------------------------------------
function FindMatchingFile(var F: TSearchRec): Integer;
var
  LocalFileTime: TFileTime;
begin
  with F do
  begin
    while FindData.dwFileAttributes and ExcludeAttr <> 0 do
      if not FindNextFile(FindHandle, FindData) then
      begin
        Result := GetLastError;
        Exit;
      end;
    FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
    FileTimeToDosDateTime(LocalFileTime, LongRec(Time).Hi, LongRec(Time).Lo);
    Size := FindData.nFileSizeLow or Int64(FindData.nFileSizeHigh) shl 32;
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

// -----------------------------------------------------------------
// Поиск позиции подстроки в строке не зависимо от регистра символов
// -----------------------------------------------------------------
function XPOS(Const SubStr, Str : String) : Integer;
var
  StrLen, SubStrLen : Integer;
  Compare : Boolean;
  I, J : Integer;
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
      Compare := Compare and (UpCase(Str[J+I]) = UpCase(SubStr[J])); // Привести символы к верхнему регистру и сравнить
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