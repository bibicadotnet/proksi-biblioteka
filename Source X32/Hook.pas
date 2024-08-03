unit Hook;

interface

uses
  Windows;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
function  CODEOFFSET(NEWADDR, OLDADDR: DWORD): DWORD;
procedure REGBLOCKER(MODULNUM : BYTE);

type
  CODEJPM = packed record              // Структура для формирования функции-моста
  DATA        : array [0..4] of byte;  // Массив для храния начального кода перехватываемой функции. В 32-х битной ОС это 5 байт.
  JMP         : Byte;                  // Поле для записи опкода инструкции JMP     | $E9
  JMPOFFSET   : DWORD;                 // Поле для записи аргумента инструкции JMP  | DWORD
  end;

var
  EPCODE : packed record               // Структура для формирования функции-моста точки входа
  CALL        : Byte;                  // Поле для записи опкода инструкции CALL    | $E8
  CALLOFFSET  : DWORD;                 // Поле для записи аргумента инструкции CALL | DWORD
  JMP         : Byte;                  // Поле для записи опкода инструкции JMP     | $E9
  JMPOFFSET   : DWORD;                 // Поле для записи аргумента инструкции JMP  | DWORD
  end;

  UPTCODE : CODEJPM;                   // Для формирования функции-моста UpdateProcThreadAttribute
  LDRCODE : CODEJPM;                   // Для формирования функции-моста LdrLoadDll
  KEYCODE : CODEJPM;                   // Для формирования функции-моста NtCreateKey
  CRDCODE : CODEJPM;                   // Для формирования функции-моста CreateDirectoryW

  HMODULE  : THANDLE;                  // Переменная для хранения дискриптора модуля
  BLOK1    : BOOLEAN;
  BLOK2    : BOOLEAN;
  DATAADDR : DWORD;                    // Переменная для хранения адреса модуля
  DATASIZE : DWORD;                    // Переменная для хранения размера секции модуля

implementation

// Функция установливает перехват
procedure CodeHook(OldProcAddress, NewProcAddress: pointer; OPT : byte = 0);
var
  // структура для обычного пехвата через JMP NEAR OFFSET
  CODE    : packed record
  JMP    : BYTE;                       // Поле для записи опкода инструкции JMP     | $E9
  OFFSET : DWORD;                      // Поле для записи аргумента инструкции JMP  | DWORD
  end;
  Protect : DWORD;                     // Переменная для хранения параметров доступа к странице памяти
  VALUE   : DWORD;                     // Переменная для функции WriteProcessMemory
const
  HANDLE = DWORD(-1);
begin

  if OPT = 1 then  // Это для создание моста при перехвате точки входа
  begin
    // Изменить параметры доступа к памяти где расположена структура EPCODE
    if not VirtualProtect(ADDR(EPCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци точки входа в структуру EPCODE. Это инструкция CALL.
    ReadProcessMemory(HANDLE, OldProcAddress, Addr(EPCODE), 5, VALUE);
    // Расчитать новое смещение для инструкции CALL и записать его значение в поле структуры
    EPCODE.CALL := $E8;
    EPCODE.CALLOFFSET := EPCODE.CALLOFFSET + CODEOFFSET(DWORD(ADDR(EPCODE)), DWORD(OldProcAddress)) + 5;
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    EPCODE.JMP  := $E9;
    EPCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(EPCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 2 then  // Это для создание моста при перехвате UpdateProcThreadAttribute
  begin
    // Изменить параметры доступа к памяти где расположена структура UPTCODE
    if not VirtualProtect(ADDR(UPTCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру UPTCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(UPTCODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    UPTCODE.JMP := $E9;
    UPTCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(UPTCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 3 then  // Это для создание моста при перехвате LdrLoadDll
  begin
    // Изменить параметры доступа к памяти где расположена структура LDRCODE
    if not VirtualProtect(ADDR(LDRCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру LDRCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(LDRCODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    LDRCODE.JMP := $E9;
    LDRCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(LDRCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 4 then  // Это для создание моста при перехвате NtCreateKey
  begin
    // Изменить параметры доступа к памяти где расположена структура KEYCODE
    if not VirtualProtect(ADDR(KEYCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру KEYCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(KEYCODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    KEYCODE.JMP := $E9;
    KEYCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(KEYCODE)), DWORD(OldProcAddress));
  end;

  if OPT = 5 then  // Это для создание моста при перехвате CreateDirectoryW
  begin
    // Изменить параметры доступа к памяти где расположена структура CRDCODE
    if not VirtualProtect(ADDR(CRDCODE), 10, PAGE_EXECUTE_READWRITE, Protect) then exit;
    // Схранить начало исходной функци в структуру CRDCODE
    ReadProcessMemory(HANDLE, OldProcAddress, ADDR(CRDCODE), 5, VALUE);
    // Формирование кода прыжка для возврата. Расчитать смещение и записать его значение в поле структуры
    CRDCODE.JMP := $E9;
    CRDCODE.JMPOFFSET := CODEOFFSET(DWORD(ADDR(CRDCODE)), DWORD(OldProcAddress));
  end;

  // Формирование прыжка в прокси функцию в теле исходной функции
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
  else
    begin
      Result := OLDADDR - NEWADDR;
      Result := Result - 5;
    end;
end;

// Поиск и замена последовательности в памяти
procedure REGBLOCKER(MODULNUM : BYTE);
const
  SEARSH   : array [0..38] of Byte = ($83,$3D,$FF,$FF,$FF,$FF,$00,$0F,$84,$FF,$FF,$00,$00,$83,$3D,$FF,$FF,$FF,$FF,$00,$0F,$84,$FF,$FF,$00,$00,$83,$3D,$FF,$FF,$FF,$FF,$00,$0F,$84,$FF,$FF,$00,$00);
  SEARCHM  : array [0..38] of Byte = ($00,$00,$01,$01,$01,$01,$00,$00,$00,$01,$01,$00,$00,$00,$00,$01,$01,$01,$01,$00,$00,$00,$01,$01,$00,$00,$00,$00,$01,$01,$01,$01,$00,$00,$00,$01,$01,$00,$00);
  REPLACE  : array [0..38] of Byte = ($83,$3D,$FF,$FF,$FF,$FF,$00,$0F,$81,$FF,$FF,$00,$00,$83,$3D,$FF,$FF,$FF,$FF,$00,$0F,$81,$FF,$FF,$00,$00,$83,$3D,$FF,$FF,$FF,$FF,$00,$0F,$81,$FF,$FF,$00,$00);
  REPLACEM : array [0..38] of Byte = ($00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$00,$00,$00);
var
  DOSHeader     : PImageDosHeader;                                    // Переменная для хранения Dos-заголовока
  NTHeader      : PImageNtHeaders;                                    // Переменная для хранения PE-заголовка
  SectionHeader : PImageSectionHeader;                                // Переменная дя хранения заголовка секции
  ASTR : String;                                                      // Переменная для хранения имени секции
  i    : LONGWORD;                                                    // Преременная для цикла поиска в пределах памяти процесса
  j    : BYTE;                                                        // Переменная для цикла поиска в пределах размера сигнатуры
  Protect : DWORD;
  BUFFER : array [0..38] of BYTE;
  RESULT : BOOLEAN;
begin
  if MODULNUM = 1 then BLOK1 := TRUE;                                 // Блокировка первого модуля выполнена
  if MODULNUM = 2 then BLOK2 := TRUE;                                 // Блокировка второго модуля выполнена
  // 1. Получить адрес и размер секции
  DOSHeader := POINTER(HMODULE);                                      // Прочитать DOS заголовок модуля
  NTHeader  := POINTER(DWORD(DOSHeader) + DWORD(DOSHeader._lfanew));  // Прочитать NT заголовок модуля
  SectionHeader := POINTER(DWORD(NTHeader) + NTheader.FileHeader.SizeOfOptionalHeader + SizeOF(NTheader.FileHeader) +  SizeOF(NTheader.Signature)); // Прочитать заголовок первой секции
  // 2. Преобразовать имя секции в строку
  for i := 0 to 7 do
  begin
    Astr := Astr + chr(SectionHeader.Name[i]);
  end;
  // 3. Получит адрес и размер секции с именем '.text' и выполнить поиск и замену
  if Pchar(Astr) = '.text' then
  begin
    DATAADDR := SectionHeader.VirtualAddress + HMODULE;               // Адрес начала данных секции
    DATASIZE := SectionHeader.SizeOfRawData;                          // Размер данных секции
    for i := 0 to DATASIZE - 39 do                                    // Цикл поиска последовательности в сеции
    begin
      CopyMemory(ADDR(BUFFER), POINTER(DATAADDR), 39);                // Скопировать в буфер из памяти секции 39 байт
      RESULT := TRUE;                                                 // Начальное значение результата совпадения
      for j := 0 to 38 do                                             // Цикл проверки совпадения сигнатуры
      begin
        RESULT := RESULT and (BUFFER[j] = SEARSH[j]);                 // Установить при совпадении или снять при отличии
        if SEARCHM[j] = $01 then RESULT := True;                      // Установить по маске поиска
        if RESULT = False then break;                                 // Если нет совпадений то прервать цикл
      end;
      if RESULT = True then                                           // Если совпадение найдено тогда выполнить замену
      begin
        // MessageBox(0, pchar(Astr), 'Найдено совпадение', MB_OK);
        for j := 0 to 38 do if REPLACEM[j] = $01 then BUFFER[j] := REPLACE[j];
        if not VirtualProtect(POINTER(DATAADDR), 39, PAGE_EXECUTE_READWRITE, Protect) then exit;
        CopyMemory(POINTER(DATAADDR), ADDR(BUFFER), 39);
        VirtualProtect(POINTER(DATAADDR), 39, Protect, Protect);
        break;
      end;
      inc(DATAADDR);                                                  // Увеличить значение адреса данных
    end;
  end;
end;

end.