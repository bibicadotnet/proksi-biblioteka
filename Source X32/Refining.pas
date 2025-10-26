unit Refining;

interface

uses
  Windows,
  Parametrs,
  Hook,
  Utils;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type

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

  PAddrInfo = Pointer;        // Нетипизированный указатель
  AddrInfo = packed record
    ai_flags: Integer;        // Флаги, указывающие параметры, используемые в функции getaddrinfo
    ai_family: Integer;       // Семейство адресов
    ai_socktype: Integer;     // Тип сокета
    ai_protocol: Integer;     // Тип протокола
    ai_addrlen: LongWord;     // Длина буфера в байтах, на который указывает элемент ai_addr
    ai_canonname: PChar;      // Каноническое имя для хоста
    var ai_addr: TSockAddrIn; // Указатель на структуру TSockAddrIn
    ai_next: PAddrInfo;       // Указатель PAddrInfo на следующую структуру типа TAddrInfo
  end;

TWSAOverlappedCompletionRoutine = procedure (dwError : DWORD; cbTransferred : DWORD; var lpOverlapped : WSAOVERLAPPED; dwFlags : DWORD);
TGetaddrinfo = function(const Nodename: PChar; const Servname : PChar; const hints: PAddrInfo; var pResult: PAddrInfo): Integer; stdcall;
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

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;
function Setsockopt(s: TSocket; level, optname: Integer; optval: PChar; optlen: Integer): Integer; stdcall;
function Bind(s: TSocket; var name: TSockAddrin; namelen: Integer): Integer; stdcall;
function Listen(s: TSocket; backlog: Integer): Integer; stdcall;
function Getaddrinfo(const Nodename: PChar; const Servname : PChar; const hints: PAddrInfo; var pResult: PAddrInfo): Integer; stdcall;                 

implementation

// *******************************************
//    Реализация функций доступа к интернет
// *******************************************

// Функция поиска положения адреса в HTTP запросах
function Host(var lpBuffers: WSABuf; var AddrPos: integer): boolean;
const
  SEARSH   : array [0..15] of Byte = ($48,$54,$54,$50,$2F,$31,$2E,$31,$0D,$0A,$48,$6F,$73,$74,$3A,$20); // HTTP/1.1 + перевод строки + Host: + пробел
  SEARCHM  : array [0..15] of Byte = ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$00,$00,$00,$00); // Маска поиска
var
  Buf : array of Byte;
  Cmp : boolean;
  Len: integer;
  i : integer;
  X : integer;
begin
  AddrPos := 0;
  Cmp := False;
  Len := lpBuffers.Len;
  if Len > 15 then
  begin
    SetLength(Buf, Len);
    CopyMemory(Addr(buf[0]), lpBuffers.buf, Len);
    for X := 0 to Len - 15 do                       // Цикл проверки буфера от начала
    begin
      for i := 0 to 15 do                           // Цикл проверки последовательности
      begin
        Cmp := Buf[X + i] = SEARSH[i];
        if SEARCHM[i] = $01 then Cmp := True;
        if Cmp = False then break;
      end;
      if Cmp = True then AddrPos := X + 16;         // Положение адреса в данных
      if Cmp = True then break;
    end;
  end;
  Buf := nil;
  if Cmp = True then Result := True else Result := False;
end;

// Функция поиска идентификатора сообщения ClientHello в HTTPS запросах
function ClientHello(var lpBuffers: WSABuf): boolean;
const
  SEARSH   : array [0..5] of Byte = ($16,$03,$01,$FF,$FF,$01); // Тип + Версия + Размер + Тип сообщения
  SEARCHM  : array [0..5] of Byte = ($00,$00,$01,$01,$01,$00); // Маска поиска
var
  Buf : array [0..5] of Byte;
  Cmp : boolean;
  i : integer;
begin
  Result := False;
  if lpBuffers.Len > 5 then
  begin
    CopyMemory(Addr(buf), lpBuffers.buf, 6);
    for i := 0 to 5 do
    begin
      Cmp := Buf[i] = SEARSH[i];
      if SEARCHM[i] = $01 then Cmp := True;
      if Cmp = False then break;
    end;
    if Cmp = True then Result := True else Result := False;
  end;
end;

// Модифицированная функция WSASend. Проверят содержимое буфера, закрывает сокет или отправляет данные в подключенный сокет.
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
  AddrPos : Integer;

begin
  Cmp := false;
  lpCompletionRoutine := nil;
  AddrPos := 0;

  if ClientHello(lpBuffers) or Host(lpBuffers, AddrPos) then
  begin
    Len := lpBuffers.len;
    SetLength(Buf, Len);
    CopyMemory(Addr(Buf[0]), lpBuffers.buf, Len);
    // Цикл сравнения содержимого буфера со списком
    for I := 0 to REFINELISTNUM - 1 do
    begin
      for X := AddrPos to Len - REFINELIST[I].len - AddrPos do
      begin
        Cmp := TRUE;
        for Y := 0 to REFINELIST[I].len - 1 do
        begin
          Cmp := Upper(Buf[X+Y]) = Upper(REFINELIST[I].buf[Y]);
          if Cmp = False then break;
        end;
      if Cmp = True then break;
      end;
    if Cmp = True then break;
    end;
    Buf := nil;
  end;

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

// Функция getaddrinfo для получения IP адреса узла из его имени
function Getaddrinfo(const Nodename: PChar; const Servname : PChar; const hints: PAddrInfo; var pResult: PAddrInfo): Integer; stdcall;
var
  Cmp : boolean;
  I: integer;
  Name: String;
begin
  Cmp := false;
  for I := 0 to REFINELISTNUM - 1 do    // Цикл сравнения имени со списком
  begin
    Cmp := false;
    Name := '';
    Name := PCHAR(REFINELIST[I].buf); // При таком присвоении в последнем элементе массива обязательно должен быть #0
    if XPOS(Name, Nodename) <> 0 then Cmp := true;
    if Cmp = true then break;
  end;
  // Врианты результата выполнения функции
  // 11001 - Узел не найден. 11004 - Нет данных.
  SetHook(GAICODE, 0);
  if Cmp = true then Result := 11001 else Result := RAWGetaddrinfo(Nodename, Servname, hints, pResult);
  SetHook(GAICODE, 1);
end;

end.