unit Hook;

interface

uses
  Windows;

  {$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure CodeHook(OldProcAddress, NewProcAddress: pointer);
function CODEOFFSET(NEWADDR, OLDADDR: DWORD):DWORD;

implementation

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer);
var
  // структура для обычного пехвата через JMP NEAR OFFSET
  CODE    : packed record
  JMP    : Byte;         // Поле для записи опкода инструкции JMP     | $E9
  OFFSET : DWORD;        // Поле для записи аргумента инструкции JMP  | DWORD
  end;
  Protect : DWORD;        // Переменная для хранения параметров доступа к странице памяти
  VALUE   : DWORD;        // Переменная для функции WriteProcessMemory
const
  HANDLE = DWORD(-1);
begin
  CODE.JMP := $E9;
  CODE.OFFSET := DWORD (NewProcAddress) - DWORD (OldProcAddress) - 5;
  // Изменить параметры доступа к области памяти
  if not VirtualProtect(OldProcAddress, 5, PAGE_EXECUTE_READWRITE, Protect) then exit;
  // HANDLE := GetCurrentProcess; // Определить идентификатор текущего процесса
  // Вместо HANDLE можно вписать INVALID_HANDLE_VALUE - это идентификатор текущего процесса.
  WriteProcessMemory(HANDLE, OldProcAddress, Addr(CODE), 5, VALUE);
  // Восстановить прежние параметры доступа к памяти
  VirtualProtect(OldProcAddress, 5, Protect, Protect);
end;

// Функция расчета смещения
function CODEOFFSET(NEWADDR, OLDADDR: DWORD):DWORD;
begin
  if(OLDADDR < NEWADDR) then
    begin
      Result := NEWADDR - OLDADDR;
      Result := $FFFFFFFF - Result;
      Result := Result - 4;
    end
  else begin
    Result := OLDADDR - NEWADDR;
    Result := Result - 5;
  end;
end;

end.
