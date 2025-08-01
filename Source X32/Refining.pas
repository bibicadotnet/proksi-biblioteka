unit Refining;

interface

uses
  Windows,
  Hook,
  Utils;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type

  // Запись для хранения имен доменов к которым обнуляются запросы
  TDomainList = record
    len : byte;
    buf : array of AnsiChar;
  end;

  // Запись для функции WSASend
  WSABUF = record
    len: Cardinal;
    buf: PAnsiChar;
  end;
  
  // Запись для функции WSASend
  WSAOVERLAPPED = record
    Internal: DWORD;
    InternalHigh : DWORD;
    Offset : DWORD;
    OffsetHigh : DWORD;
    hEvent : THANDLE;
  end;

  TSocket = Cardinal; // Идентификатор сокета

    SunB = packed record                  // Структура представления адреса
    B1: Char;                           // в виде 4-х байт
    B2: Char;
    B3: Char;
    B4: Char;
  end;

  SunW = packed record                   // Структура представления адреса
    W1: Word;                            // в виде 2-х слов
    W2: Word;
  end;

  inaddr = record                        // Структура для хранения IP-адреса
    case integer of                      // Вариант представления адреса
      0: (SB: SunB);                     // как последовательнось четырех байт
      1: (SW: SunW);                     // как последовательность двух двухбайтных слов
      2: (Saddr: Longint);               // как одно четырехбайтное слово
  end;
  TInAddr = inaddr;

  sockaddrin = record                     // Структура для сокета
    case Integer of                       // Вариант представления данных
      0: (
          sinfamily: Word;                // Семейство адресов (2 байта)
          sinport: Word;                  // Номер порта       (2 байта)
          sinaddr: TInAddr;               // Структура с IP-адресом (4 байта)
          sinzero: array[0..7] of Char    // Дополнение до размера структуры sockaddr (8 байт)
         );
      1: (
          safamily: Word;                 // Семейство адресов (2 байта)
          sadata: array[0..13] of Char    // Данные (14 байт)
         )
  end;
  TSockAddrIn = sockaddrin;

TWSAOverlappedCompletionRoutine = procedure (dwError : DWORD; cbTransferred : DWORD; var lpOverlapped : WSAOVERLAPPED; dwFlags : DWORD);

TWSASend = function(
                    S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                    var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                    ): Integer; stdcall;

TClosesocket = function(s: TSocket): Integer; stdcall;
TSetsockopt = function(s: TSocket; level, optname: Integer; optval: PChar; optlen: Integer): Integer; stdcall;

VAR
  RAWWSASend : TWSASend;              // Оригинальная функция WSASend
  RAWSetsockopt : TSetsockopt;        // Оригинальная функция Setsockopt
  Closesocket : TClosesocket;         // Функция закрытия сокета
  REFINELIST : array of TDomainList;  // Массив записей для обнуления запросов к гугле и его доменам
  REFINELISTNUM : integer;            // Число эдементов массива списка обнуления
  BCTOFF : boolean;                   // Переменная для отключения широковещательных рассылок
  ECHOFF : boolean;                   // Переменная для отключения Encrypted Client Hello

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;
function Setsockopt(s: TSocket; level, optname: Integer; optval: PChar; optlen: Integer): Integer; stdcall;
function Bind(s: TSocket; var name: TSockAddrin; namelen: Integer): Integer; stdcall;
function Listen(s: TSocket; backlog: Integer): Integer; stdcall;                 

implementation

// *******************************************
//    Реализация функций доступа к интернет
// *******************************************

// Функция отправляет данные в подключенный сокет.
function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;

Var
  I: integer;
  Cmp : boolean;
  X, Y: integer;
  Buf : array of AnsiChar;
  Len: Integer;

begin
  Cmp := false;
  lpCompletionRoutine := nil;
  Len := lpBuffers.len;
  SetLength(Buf, lpBuffers.len);
  CopyMemory(Addr(Buf[0]), lpBuffers.buf, Len);
  // Цикл сравнения содержимого буффера со списком
  for I := 0 to REFINELISTNUM - 1 do
  begin
    for X := 0 to Len - REFINELIST[I].len do
      begin
      Cmp := TRUE;
      for Y := 0 to REFINELIST[I].len - 1 do
        begin
        Cmp := UpCase(Buf[X+Y]) = UpCase(REFINELIST[I].buf[Y]);
        if Cmp = False then break;
        end;
      if Cmp = True then break;
      end;
  if Cmp = True then break;
  end;
  Buf := nil;

  SetHook(WSACODE, 0);
  if Cmp = true then Closesocket(s); // Закрыть сокет.
  // Врианты результата выполнения функции WSASend
  // 0 - выполнена без ошибок. 10050 - Сеть не работает. 10053 - Соединение прервано. 10057 - Сокет не подключен.
  if Cmp = true then Result := 10050 else Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine);
  SetHook(WSACODE, 1);
end;

// Функция задаёт парамтры сокета. level  - это уровень,  optname - это опция
function Setsockopt(s: TSocket; level, optname: Integer; optval: PChar; optlen: Integer): Integer; stdcall;
var
  Cmp : boolean;
begin
  Cmp := false;

  if ECHOFF = True then   // Отключить использование ECH и DoH
  begin
    if (level = $FFFF) and (optname = $3005) then Cmp := true; // Игнорирование свойства SO_RANDOMIZE_PORT отлючает ECH и DoH
    if level = $29 then Cmp := true;                           // Не использовать семейство адресов IP6
  end;

  if BCTOFF = True then   // Отключить широковещательные рассылки
  begin
    if (level = $FFFF) and (optname = $20) then Cmp := true;   // Не настраивать сокет для отправки широковещательных данных
    if (level = $0) and (optname = $9) then Cmp := true;       // Не назначать интерфейс для многоадресной рассылки
    if (level = $0) and (optname = $C) then Cmp := true;       // Не присоединять сокет к предоставленной группе многоадресной рассылки
    if level = $29 then Cmp := true;                           // Не использовать семейство адресов IP6
  end;

  SetHook(SSOCODE, 0);
  if Cmp = true then Closesocket(s);
  if Cmp = true then Result := 10050 else Result := RAWSetsockopt (s, level, optname, optval, optlen);
  SetHook(SSOCODE, 1);
end;

// Функция Bind используется для связи сокета с адресом
function Bind(s: TSocket; var name: TSockAddrin; namelen: Integer): Integer; stdcall;
begin
  Closesocket(s);
  Result := 10050;
end;

// Функция Listen переводит сокет в режим ожидания запросов от клиентов
function Listen(s: TSocket; backlog: Integer): Integer; stdcall;
begin
  Closesocket(s);
  Result := 10050;
end;

end.