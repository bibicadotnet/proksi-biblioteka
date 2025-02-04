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

  TSocket = Cardinal; // Идентификатор сокета

TWSAOverlappedCompletionRoutine = procedure (dwError : DWORD; cbTransferred : DWORD; var lpOverlapped : WSAOVERLAPPED; dwFlags : DWORD);

TWSASend = function(
                    S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                    var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                    ): Integer; stdcall;

TClosesocket = function(s: TSocket): Integer; stdcall;

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;

VAR
  RAWWSASend : TWSASend;              // Оригинальная функция WSASend   
  Closesocket : TClosesocket;         // Функция закрытия сокета
  REFINELIST : array of TDomainList;  // Массив записей для обнуления запросов к гугле и его доменам
  REFINELISTNUM : integer;            // Число эдементов массива списка обнуления

implementation

// *******************************************
//    Реализация функций доступа к интернет
// *******************************************

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
  if Cmp = true then Closesocket(s); // Закрыть сокет.
  // Врианты результата выполнения функции WSASend
  // 0 - выполнена без ошибок. 10050 - Сеть не работает. 10053 - Соединение прервано. 10057 - Сокет не подключен.
  if Cmp = true then Result := 10053 else Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine);
  SetHook(WSACODE, 1);
end;

end.