unit Refining;

interface

uses
  Windows,
  Utils;
  //WinInet;

type
{
  SunB = packed record
    s_b1, s_b2, s_b3, s_b4: Byte;
  end;

  SunC = record
    s_c1, s_c2, s_c3, s_c4: Char;
  end;

  SunW = packed record
    s_w1, s_w2: Word;
  end;

  TInAddr = record
    case integer of
      0: (S_un_b: SunB);
      1: (S_un_c: SunC);
      2: (S_un_w: SunW);
      3: (S_addr: Cardinal);
  end;

  TSockAddr = record
    case Integer of
      0: (sin_family: Word;
          sin_port: Word;
          sin_addr: TInAddr;
          sin_zero: array[0..7] of Char);
      1: (sa_family: Word;
          sa_data: array[0..13] of Char)
  end;
}
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
{
type
  sockaddr = record
    sa_family: Word;                // address family
    sa_data: array [0..13] of Char; // up to 14 bytes of direct address
  end;

  WSAMSG = record
    var name: sockaddr; // Remote address
    namelen: Integer; // Remote address length
    var lpBuffers: WSABUF; // Data buffer array
    dwBufferCount: ULONG; // Number of elements in the array
    Control: WSABUF; // Control buffer
    dwFlags: ULONG; // dwFlags;
  end;
}
  TSocket = Cardinal;

{
  TSockAddr = record
    sa_family: Word;
    sa_data: array[0..13] of Char;
  end;
}

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

{
function WSASendTo(
                   s: TSocket; var lpBuffers: WSABUF; dwBufferCount: DWORD; lpNumberOfBytesSent: LPDWORD; dwFlags: DWORD;
                   const lpTo: TSockAddr; iTolen: Integer;  var lpOverlapped: WSAOVERLAPPED;
                   lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                   ): Integer; stdcall;
}

//function Send(S:TSocket; var Buf; Len,Flags:Integer):Integer;
//function SendTo(S: TSocket; var Buf; Len, Flags: Integer; var AddrTo: TSockAddr; ToLen: Integer):Integer;

//function WinHttpConnect(hSession: HINTERNET; pswzServerName: PChar; nServerPort: INTERNET_PORT; dwReserved: cardinal): HINTERNET; stdcall;
//function WinHttpOpen(pwszUserAgent: PWideChar; dwAccessType: DWORD; pwszProxyName, pwszProxyBypass: PWideChar; dwFlags: DWORD): HINTERNET; stdcall;

VAR
RAWWSASend : TWSASend;
//RAWWSASendTo : TWSASendTo;

implementation


// ***********************************************************
// Функции доступа к интернет
// ***********************************************************

{
function RecvFrom(S:TSocket;var Buf;Len,Flags:Integer; var From:TSockAddr;var FromLen:Integer):Integer;
begin
  Result := 0;
end;

function Recv(S:TSocket;var Buf;Len,Flags:Integer):Integer;
begin
  Result := 0;
end;

function bind(s: Integer; var addr: TSockAddr; namelen: Integer): Integer; stdcall;
begin
  Result := 0;
end;
}
{
function Send(S:TSocket; var Buf; Len, Flags:Integer):Integer;
begin
  MessageBox(0, 'Send', 'Функция', MB_OK);
  Result := 0;
end;

function SendTo(S: TSocket; var Buf; Len, Flags: Integer; var AddrTo: TSockAddr; ToLen: Integer):Integer;
begin
  MessageBox(0, 'SendTo', 'Функция', MB_OK);
  Result := 0;
end;
}

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
  //MessageBox(0, pchar(msg), 'Содержимое буффера WSASend', MB_OK);
  block := false;
  if XPOS('amazon.com', msg) <>0  then block := true;
  if XPOS('accounts.google', msg) <>0  then block := true;
  if XPOS('adgoogle', msg) <>0  then block := true;
  if XPOS('analytics.google', msg) <>0  then block := true;
  if XPOS('android.clients.google', msg) <>0  then block := true;
  if XPOS('arin.net', msg) <>0  then block := true;
  if XPOS('apps.db.ripe.net', msg) <>0  then block := true;
  if XPOS('clients2.google', msg) <>0  then block := true;
  if XPOS('clients.your-server', msg) <>0  then block := true;
  if XPOS('cloudflare', msg) <>0  then block := true;
  if XPOS('crashlytics', msg) <>0  then block := true;
  if XPOS('dl.google', msg) <>0  then block := true;
  if XPOS('googleads.g.doubleclick', msg) <>0  then block := true;
  if XPOS('googlehosted', msg) <>0  then block := true;
  if XPOS('googleadservices', msg) <>0  then block := true;
  if XPOS('googleoptimize', msg) <>0  then block := true;
  if XPOS('googlesyndication', msg) <>0  then block := true;
  if XPOS('googleusercontent', msg) <>0  then block := true;
  if XPOS('google-analytics', msg) <>0  then block := true;
  if XPOS('googleapis', msg) <>0  then block := true;
  if XPOS('googletagmanager', msg) <>0  then block := true;
  if XPOS('googleanalytics', msg) <>0  then block := true;
  if XPOS('googletagservices', msg) <>0  then block := true;
  if XPOS('gstatic', msg) <>0  then block := true;
  if XPOS('maps.google', msg) <>0  then block := true;  
  if XPOS('mtalk.google', msg) <>0  then block := true;
  if XPOS('rdap.arin.net', msg) <>0  then block := true;
  if XPOS('sb.l.google', msg) <>0  then block := true;
  if XPOS('static.doubleclick.net', msg) <>0  then block := true;
  if XPOS('unpkg.com', msg) <>0  then block := true;
  if XPOS('wide-plus.l.google', msg) <>0  then block := true;
  if XPOS('withgoogle', msg) <>0  then block := true;
  //MessageBox(0, pchar(msg), 'Содержимое буффера WSASend', MB_OK);
  Buff := nil;
  //FreeMem(Buff);
  if block = false then Result := RAWWSASend(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped,	lpCompletionRoutine) else Result := 0;
end;

{
function WSASendTo(
                   s: TSocket; var lpBuffers: WSABUF; dwBufferCount: DWORD; lpNumberOfBytesSent: LPDWORD; dwFlags: DWORD;
                   const lpTo: TSockAddr; iTolen: Integer;  var lpOverlapped: WSAOVERLAPPED;
                   lpCompletionRoutine: TWSAOverlappedCompletionRoutine
                   ): Integer; stdcall;
Var
  msg : String;
  Buff : array of Char;
  block : boolean;
begin
  SetLength(Buff, lpBuffers.len);
  Move(lpBuffers.buf[0], Buff[0], lpBuffers.len);
  msg := String(Buff) + #0;
  lpCompletionRoutine := nil;
  //MessageBox(0, pchar(msg), 'Содержимое буффера WSASend', MB_OK);
  block := false;
  if XPOS('amazon.com', msg) <>0  then block := true;
  if XPOS('accounts.google', msg) <>0  then block := true;
   if XPOS('adgoogle', msg) <>0  then block := true;
  if XPOS('analytics.google', msg) <>0  then block := true;
  if XPOS('android.clients.google', msg) <>0  then block := true;
  if XPOS('arin.net', msg) <>0  then block := true;
  if XPOS('apps.db.ripe.net', msg) <>0  then block := true;
  if XPOS('clients2.google', msg) <>0  then block := true;
  if XPOS('clients.your-server', msg) <>0  then block := true;
  if XPOS('cloudflare', msg) <>0  then block := true;
  if XPOS('crashlytics', msg) <>0  then block := true;
  if XPOS('dl.google', msg) <>0  then block := true;
  if XPOS('googleads.g.doubleclick', msg) <>0  then block := true;
  if XPOS('googleoptimize', msg) <>0  then block := true;
  if XPOS('googlesyndication', msg) <>0  then block := true;
  if XPOS('googleusercontent', msg) <>0  then block := true;
  if XPOS('googlevideo', msg) <>0  then block := true;
  if XPOS('maps.google', msg) <>0  then block := true;
  if XPOS('google-analytics', msg) <>0  then block := true;
  if XPOS('googleapis', msg) <>0  then block := true;
  if XPOS('googletagmanager', msg) <>0  then block := true;
  if XPOS('googleanalytics', msg) <>0  then block := true;
  if XPOS('googletagservices', msg) <>0  then block := true;
  if XPOS('gstatic', msg) <>0  then block := true;
  if XPOS('mtalk.google', msg) <>0  then block := true;
  if XPOS('rdap.arin.net', msg) <>0  then block := true;
  if XPOS('sb.l.google', msg) <>0  then block := true;
  if XPOS('static.doubleclick.net', msg) <>0  then block := true;
  if XPOS('unpkg.com', msg) <>0  then block := true;
  if XPOS('wide-plus.l.google', msg) <>0  then block := true;
  if XPOS('withgoogle', msg) <>0  then block := true;
  //MessageBox(0, pchar(msg), 'Содержимое буффера WSASendTo', MB_OK);
  Buff := nil;
  if block = false then Result := RAWWSASendTo(S, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine) else Result := 0;

end;
}

{
function WSARecvFrom(
                     S: TSocket; var lpBuffers: WSABuf; dwBufferCount: DWORD; var NumberOfBytesRecvd: DWORD;	var Flags: DWORD;
                     var lpFrom: TSockAddr;	lpFromLen: PInteger; var lpOverlapped: WSAOverlapped;
                     lpCompletionRoutine:TWSAOverlappedCompletionRoutine
                     ): Integer; stdcall;
begin
  Result := 0;
end;
}

{
function WinHttpConnect(hSession: HINTERNET; pswzServerName: PChar; nServerPort: INTERNET_PORT; dwReserved: cardinal): HINTERNET; stdcall;
begin
  Result := 0;
end;

function WinHttpOpen(pwszUserAgent: PWideChar; dwAccessType: DWORD; pwszProxyName, pwszProxyBypass: PWideChar; dwFlags: DWORD): HINTERNET; stdcall;
begin
  Result := 0;
end;
}

end.
