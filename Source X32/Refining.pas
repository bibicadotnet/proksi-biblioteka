unit Refining;

interface

uses
  Windows,
  Utils;

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
{
TWSASendTo = function(
                        s: TSocket; var lpBuffers: WSABUF; dwBufferCount: DWORD; lpNumberOfBytesSent: LPDWORD; dwFlags: DWORD;
                        const lpTo: TSockAddr; iTolen: Integer;  var lpOverlapped: WSAOVERLAPPED;
                        lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                       ): Integer; stdcall;
}

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;

VAR
RAWWSASend : TWSASend;

implementation

// ***********************************************************
// Функции доступа к интернет
// ***********************************************************

function WSASend(
                 S: TSocket;	var lpBuffers: WSABuf; dwBufferCount: DWORD; var lpNumberOfBytesSent: DWORD; dwFlags: DWORD;
                 var lpOverlapped: WSAOverlapped;	lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                 ): Integer; stdcall;
Var
  msg : String;
  Buff : array of Char;
  //Buff : PChar;
  block : boolean;
begin
  SetLength(Buff, lpBuffers.len);
  //GetMem(buff, lpBuffers.len);
  Move(lpBuffers.buf[0], Buff[0], lpBuffers.len);
  msg := String(Buff) + #0;
  lpCompletionRoutine := nil;
  block := false;
  if XPOS('amazon.com', msg) <> 0  then block := true;
  if XPOS('accounts.google', msg) <> 0  then block := true;
  if XPOS('adgoogle', msg) <> 0  then block := true;
  if XPOS('analytics.google', msg) <> 0  then block := true;
  if XPOS('android.clients.google', msg) <>0  then block := true;
  if XPOS('arin.net', msg) <> 0  then block := true;
  if XPOS('apps.db.ripe.net', msg) <> 0  then block := true;
  if XPOS('clients2.google', msg) <> 0  then block := true;
  if XPOS('clients.your-server', msg) <> 0  then block := true;
  if XPOS('cloudflare', msg) <> 0  then block := true;
  if XPOS('crashlytics', msg) <> 0  then block := true;
  if XPOS('dl.google', msg) <> 0  then block := true;
  if XPOS('googleads.g.doubleclick', msg) <> 0  then block := true;
  if XPOS('googlehosted', msg) <> 0  then block := true;
  if XPOS('googleadservices', msg) <> 0  then block := true;
  if XPOS('googleoptimize', msg) <> 0  then block := true;
  if XPOS('googlesyndication', msg) <> 0  then block := true;
  if XPOS('googleusercontent', msg) <> 0  then block := true;
  if XPOS('google-analytics', msg) <> 0  then block := true;
  if XPOS('googleapis', msg) <> 0  then block := true;
  if XPOS('googletagmanager', msg) <> 0  then block := true;
  if XPOS('googleanalytics', msg) <> 0  then block := true;
  if XPOS('googletagservices', msg) <> 0  then block := true;
  if XPOS('gstatic', msg) <> 0  then block := true;
  if XPOS('maps.google', msg) <> 0  then block := true;  
  if XPOS('mtalk.google', msg) <> 0  then block := true;
  if XPOS('rdap.arin.net', msg) <> 0  then block := true;
  if XPOS('sb.l.google', msg) <> 0  then block := true;
  if XPOS('static.doubleclick.net', msg) <> 0  then block := true;
  if XPOS('unpkg.com', msg) <> 0  then block := true;
  if XPOS('wide-plus.l.google', msg) <> 0  then block := true;
  if XPOS('withgoogle', msg) <> 0  then block := true;
  Buff := nil;
  //FreeMem(Buff);
  if block = false then Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine) else Result := 0;
end;

end.