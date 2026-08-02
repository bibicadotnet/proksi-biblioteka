unit Refining;

interface

uses
  SysTypFunc,
  Parametrs,
  Hook,
  Utils;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type

  BuffAnsi = array of AnsiChar;    // Тип данных для функций Host, ClientHello, WSASend

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
    B1: Byte;                           // в виде 4-х байт
    B2: Byte;
    B3: Byte;
    B4: Byte;
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
          sinzero: array[0..7] of Byte    // Дополнение до размера структуры sockaddr (8 байт)
         );
      1: (
          safamily: Word;                 // Семейство адресов (2 байта)
          sadata: array[0..13] of Byte    // Данные (14 байт)
         )
  end;
  TSockAddrIn = sockaddrin;

  sockaddr = record
    sinfamily: Word;
    sinzero: array[0..13] of Byte;
  end;
  TSockAddr = sockaddr;

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
                    S: TSocket;	const lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                    var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                    ): Integer; stdcall;
TWSASendTo = function(
                      S: TSocket; const lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                      const lpTo: TSockAddr; iTolen: Integer; var lpOverlapped: WSAOverlapped; lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                      ): Integer; stdcall;
TClosesocket = function(s: TSocket): Integer; stdcall;
TSetsockopt = function(s: TSocket; level, optname: Integer; optval: PByte; optlen: Integer): Integer; stdcall;

VAR
  RAWWSASend : TWSASend;              // Оригинальная функция WSASend
  RAWWSASendTo : TWSASendTo;          // Оригинальная функция WSASendTo
  RAWSetsockopt : TSetsockopt;        // Оригинальная функция Setsockopt
  RAWGetaddrinfo : Tgetaddrinfo;      // Оригинальная функция Getaddrinfo
  Closesocket : TClosesocket;         // Функция закрытия сокета

function WSASend(
                 S: TSocket;	const lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;
function WSASendTo(S: TSocket; const lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                   const lpTo: TSockAddr; iTolen: Integer; var lpOverlapped: WSAOverlapped; lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                  ): Integer; stdcall;
function Setsockopt(s: TSocket; level, optname: Integer; optval: PByte; optlen: Integer): Integer; stdcall;
function Listen(s: TSocket; backlog: Integer): Integer; stdcall;
function Getaddrinfo(const Nodename: PChar; const Servname : PChar; const hints: PAddrInfo; var pResult: PAddrInfo): Integer; stdcall;                 

implementation

// *******************************************
//    Реализация функций доступа к интернет
// *******************************************

// Функция поиска DNS записи в UDP запросах
function DNS(const Buf: BuffAnsi; Len : integer; var Name : String; var HTTPS: boolean): boolean;
const
  SEARSH   : array [0..11] of Byte = ($FF,$FF,$01,$00,$00,$01,$00,$00,$00,$00,$00,$00); // ID + флаги
  SEARCHM  : array [0..11] of Byte = ($01,$01,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00); // Маска поиска
var
  Cmp : boolean;
  I : integer;
  X : integer;
  L : integer;
  P : integer;

begin
  Cmp := False;
  Result := False;
  P := 0;

  if Len > 11 then                                  // Если размер данных больше 11
  begin
    for X := 0 to Len - 11 do                       // Цикл проверки буфера от начала
    begin
      for I := 0 to 11 do                           // Цикл проверки последовательности
      begin
        Cmp := Byte(Buf[X + I]) = SEARSH[i];        // Сравнить байты
        if SEARCHM[i] = $01 then Cmp := True;       // Использовать маску (для любого байта)
        if Cmp = False then break;                  // Прервать цикл при первом же отличии
      end;
      if Cmp = True then P := X + 12;               // Положение размера первой метки в данных
      if Cmp = True then break;                     // Прервать цикл
    end;

    if Cmp = True then                              // Декодирование меток
    begin
      while (P < Len) do
      begin
        L := Byte(Buf[P]);                                                  // Считать размер метки
        Inc(P, 1);                                                          // Перейти на позицию метки
        if (L = 0) then Break;                                              // Прервать цикл если метка нулевая или если конец меток
        if (Name <> '') then  Name := Name + '.';                           // Добавить точку после каждой метки
        for I := P to P + L - 1 do Name := Name + Buf[I];                   // Считать метку из буфера
        Inc(P, L);                                                          // Увеличить P на L (перейти на позицию размера следующей метки)
      end;
    end;

    if Cmp = True then             // Определение типа записи HTTPS
    begin
      if (Byte(Buf[Len-3]) = $41) and (Byte(Buf[Len-1]) = $01) then HTTPS := True else HTTPS := False;
    end;
  end;
  if Cmp = True then Result := True;
end;

// Функция поиска положения адреса в HTTP запросах
function Host(const Buf: BuffAnsi; Len: Integer; var AddrPos: integer): boolean;
const
  SEARSH   : array [0..15] of Byte = ($48,$54,$54,$50,$2F,$31,$2E,$31,$0D,$0A,$48,$6F,$73,$74,$3A,$20); // HTTP/1.1 + перевод строки + Host: + пробел
  SEARCHM  : array [0..15] of Byte = ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$01,$00,$00,$00,$00,$00); // Маска поиска
var
  Cmp : boolean;
  i : integer;
  X : integer;
begin
  AddrPos := 0;
  Cmp := False;
  Result := False;
  if Len > 15 then
  begin
    for X := 0 to Len - 15 do                       // Цикл проверки буфера от начала
    begin
      for i := 0 to 15 do                           // Цикл проверки последовательности
      begin
        Cmp := Byte(Buf[X + i]) = SEARSH[i];
        if SEARCHM[i] = $01 then Cmp := True;
        if Cmp = False then break;
      end;
      if Cmp = True then AddrPos := X + 16;         // Положение адреса в данных
      if Cmp = True then break;
    end;
  end;
  if Cmp = True then Result := True;
end;

// Функция поиска идентификатора сообщения ClientHello в HTTPS запросах
function ClientHello(const Buf: BuffAnsi; Len: Integer): boolean;
const
  SEARSH   : array [0..5] of Byte = ($16,$03,$01,$FF,$FF,$01); // Тип + Версия + Размер + Тип сообщения
  SEARCHM  : array [0..5] of Byte = ($00,$00,$01,$01,$01,$00); // Маска поиска
var
  Cmp : boolean;
  i : integer;
begin
  Result := False;
  if Len > 5 then
  begin
    for i := 0 to 5 do
    begin
      Cmp := Byte(Buf[i]) = SEARSH[i];
      if SEARCHM[i] = $01 then Cmp := True;
      if Cmp = False then break;
    end;
    if Cmp = True then Result := True;
  end;
end;

// Модифицированная функция WSASend. Проверят содержимое буфера, закрывает сокет или отправляет данные в подключенный сокет.
function WSASend(
                 S: TSocket;	const lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;

Var
  I: integer;
  Cmp : boolean;
  X, Y: integer;
  Buf : BuffAnsi;
  Len: Integer;
  AddrPos : Integer;

begin
  Cmp := false;
  // Врианты результата выполнения функции WSASend
  // 0 - выполнена без ошибок. 10050 - Сеть не работает. 10053 - Соединение прервано. 10057 - Сокет не подключен.
  Result := 10050;
  lpCompletionRoutine := nil;
  AddrPos := 0;

  Len := lpBuffers.len;
  SetLength(Buf, Len);
  CopyMemory(Addr(Buf[0]), lpBuffers.buf, Len);

  if ClientHello(Buf, Len) or Host(Buf, Len, AddrPos) then
  begin
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
  end;

  SetHook(WSACODE, 0);
  if Cmp = true then Closesocket(s); // Закрыть сокет.
  if Cmp = False then Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine);
  SetHook(WSACODE, 1);
end;

// Функция WSASendTo используется в протоколах UDP
// В том числе в DNS запросах. Не используется если DNSOFF=1.
function WSASendTo(s: TSocket; const lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                   const lpTo: TSockAddr; iTolen: Integer; var lpOverlapped: WSAOverlapped; lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                  ): Integer; stdcall;
Var
  I: integer;
  Cmp : boolean;
  Buf : BuffAnsi;
  Len: Integer;
  Name : String;
  HostName : String;
  HTTPS : boolean;
begin
  Cmp := False;
  HTTPS := False;
  // Врианты результата выполнения функции WSASendTo
  // 0 - выполнена без ошибок. 10050 - Сеть не работает. 10053 - Соединение прервано. 10057 - Сокет не подключен.
  Result := 10050;
  Name := '';
  HostName := '';
  lpCompletionRoutine := nil;

  Len := lpBuffers.len;
  SetLength(Buf, Len);
  CopyMemory(Addr(Buf[0]), lpBuffers.buf, Len);

  if DNS(Buf, Len, HostName, HTTPS) then         // Если в данных DNS запроса
  begin
    for I := 0 to REFINELISTNUM - 1 do
    begin
      Cmp := false;
      SetString(Name, PCHAR(REFINELIST[I].buf), REFINELIST[I].Len);
      if HostName <> '' then if XPOS(Name, HostName) <> 0 then Cmp := True;
      if Cmp = True then break;
    end;
    if ECHOFF = True then if HTTPS = True then Cmp := True;
  end;

  SetHook(WSTCODE, 0);
  if Cmp = True then CloseSocket(s); // Закрыть сокет.
  if Cmp = False then Result := RAWWSASendTo(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped,	lpCompletionRoutine);
  SetHook(WSTCODE, 1);
end;

// Функция задаёт парамтры сокета. level  - это уровень,  optname - это опция
function Setsockopt(s: TSocket; level, optname: Integer; optval: PByte; optlen: Integer): Integer; stdcall;
var
  Cmp : boolean;
begin
  Cmp := false;
  Result := 10050;

  if BCTOFF = True then   // Отключить широковещательные рассылки
  begin
    if (level = $FFFF) and (optname = $20) then Cmp := true;   // Не настраивать сокет для отправки широковещательных данных
    if (level = $0) and (optname = $9) then Cmp := true;       // Не назначать интерфейс для многоадресной рассылки
    if (level = $0) and (optname = $C) then Cmp := true;       // Не присоединять сокет к предоставленной группе многоадресной рассылки
    if level = $29 then Cmp := true;                           // Не использовать семейство адресов IP6
  end;

  SetHook(SSOCODE, 0);
  if Cmp = True then Closesocket(s);
  if Cmp = False then Result := RAWSetsockopt (s, level, optname, optval, optlen);
  SetHook(SSOCODE, 1);
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
  Result := 11001;                    // 11001 - Узел не найден. 11004 - Нет данных.
  for I := 0 to REFINELISTNUM - 1 do  // Цикл сравнения имени со списком
  begin
    Cmp := false;
    Name := '';
    SetString(Name, PCHAR(REFINELIST[I].buf), REFINELIST[I].Len);  // Скопировать символы из буфера в строку
    if (Nodename <> nil) and (String(Nodename) <> '') then if XPOS(Name, Nodename) <> 0 then Cmp := true;
    if Cmp = true then break;
  end;

  SetHook(GAICODE, 0);
  if Cmp = False then Result := RAWGetaddrinfo(Nodename, Servname, hints, pResult);
  SetHook(GAICODE, 1);
end;

end.