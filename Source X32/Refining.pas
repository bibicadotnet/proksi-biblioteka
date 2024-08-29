unit Refining;

interface

uses
  Windows,
  Utils;

{$SETPEFlAGS IMAGE_FILE_DEBUG_STRIPPED or IMAGE_FILE_LINE_NUMS_STRIPPED or IMAGE_FILE_LOCAL_SYMS_STRIPPED}

type
  WSABUF = packed record
    len: Cardinal;
    buf: PChar;
  end;

  WSAOVERLAPPED = packed record
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
  REFINELIST : array of String;   // Массив списка для обнуления запросов к гугле и его доменам
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
  Msg : String;
  Domain : String;
  Buff : array of Char;
  //Buff : PChar;
  block : boolean;
  I: integer;
begin
  SetLength(Buff, lpBuffers.len);
  //GetMem(buff, lpBuffers.len);
  Move(lpBuffers.buf[0], Buff[0], lpBuffers.len);
  Msg := String(Buff) + #0;
  lpCompletionRoutine := nil;
  block := false;
  for I := 0 to REFINELISTNUM - 1 do                         // Цикл сравнения со списком
  begin
    Domain := REFINELIST[i];                                 // Имя из списка обнуления в переменную
    if XPOS(Domain, Msg) <> 0 then block := True;            // Если имя совпадает с именем из списка установить флаг
    if block = True then break;                              // Если флаг установлен прервать цикл
  end;
  Buff := nil;
  //FreeMem(Buff);
  if block = false then Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine) else Result := 0;
end;

end.