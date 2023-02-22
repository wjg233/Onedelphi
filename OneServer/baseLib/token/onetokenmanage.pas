unit OneTokenManage;

{$mode DELPHI}{$H+}

// token管理
// 客户端连上来后 生成一个GUID tokenID当标识身份,后续提交tokenID来确保用户身份
interface

uses
  Classes, StrUtils, SysUtils, Generics.Collections,
  DB, OneILog, DateUtils, OneThread, SyncObjs, memds, BufDataset;

type
  IOneTokenItem = interface;
  TOneTokenItem = class;
  TOneTokenManage = class;
  // 角色权限 noneRegister:无需注册就能访问最低级别
  // noneRole:任何人可以访问
  // userRole:用户可以访问
  // sysUserRole:系统用户
  // sysAdminRole:系统用户且为管理员
  // superRole:超级管理员
  // platformRole:平台管理员
  TOneAuthorRole = (noneRegister, noneRole, userRole, sysUserRole, sysAdminRole,
    superRole, platformRole);

  IOneTokenItem = interface
    ['{3EF15CD4-0435-42EB-B534-C9B550E82393}']
    function ConnectionID(): string;
    procedure SetConnectionID(QValue: string);
    function TokenID(): string;
    procedure SetTokenID(QValue: string);
    function PrivateKey(): string;
    procedure SetPrivateKey(QValue: string);
    function LoginIP(): string;
    procedure SetLoginIP(QValue: string);
    function LoginMac(): string;
    procedure SetLoginMac(QValue: string);
    function LoginTime(): TDateTime;
    procedure SetLoginTime(QValue: TDateTime);
    function LoginPlatform(): string;
    procedure SetLoginPlatform(QValue: string);
    function LoginUserCode(): string;
    procedure SetLoginUserCode(QValue: string);
    function SysUserID(): string;
    procedure SetSysUserID(QValue: string);
    function SysUserName(): string;
    procedure SetSysUserName(QValue: string);
    function SysUserCode(): string;
    procedure SetSysUserCode(QValue: string);
    function SysUserType(): string;
    procedure SetSysUserType(QValue: string);
    function SysUserTable(): string;
    procedure SetSysUserTable(QValue: string);
    function ZTCode(): string;
    procedure SetZTCode(QValue: string);
    function PlatUserID(): string;
    procedure SetPlatUserID(QValue: string);
    function LastTime(): TDateTime;
    procedure SetLastTime(QValue: TDateTime);
  end;

  // 如果此token没办法满足你，你自已继承 IOneTokenItem写个
  TOneTokenItem = class(TInterfacedObject, IOneTokenItem)
  private
    // 连接ID ，长连接才有，否则这个就是假的
    FConnectionID: string;
    // 生成的TokenID唯一的
    FTokenID: string;
    // 每个token多分配一个私钥给它保证安全性
    FPrivateKey: string;
    // ***登陆信息********//
    // 登陆IP
    FLoginIP: string;
    FLoginMac: string;
    // 登陆时间
    FLoginTime: TDateTime;
    // 从哪个平台登陆 exe,web,微信，小程序
    FLoginPlatform: string;
    // 登陆代码
    FLoginUserCode: string;
    // 用户关联的用户代码ID
    FSysUserID: string;
    // 用户名称
    FSysUserName: string;
    FSysUserCode: string;
    // 用户类型
    FSysUserType: string;
    // 用户关联的表
    FSysUserTable: string;
    // 账套代码
    FZTCode: string;
    // 租户ID
    FPlatUserID: string;
    // ***登陆信息end********//
    // 最后交互时间
    FLastTime: TDateTime;
  public
    destructor Destroy; override;
  public
    function ConnectionID(): string;
    procedure SetConnectionID(QValue: string);
    function TokenID(): string;
    procedure SetTokenID(QValue: string);
    function PrivateKey(): string;
    procedure SetPrivateKey(QValue: string);
    function LoginIP(): string;
    procedure SetLoginIP(QValue: string);
    function LoginMac(): string;
    procedure SetLoginMac(QValue: string);
    function LoginTime(): TDateTime;
    procedure SetLoginTime(QValue: TDateTime);
    function LoginPlatform(): string;
    procedure SetLoginPlatform(QValue: string);
    function LoginUserCode(): string;
    procedure SetLoginUserCode(QValue: string);
    function SysUserID(): string;
    procedure SetSysUserID(QValue: string);
    function SysUserName(): string;
    procedure SetSysUserName(QValue: string);
    function SysUserCode(): string;
    procedure SetSysUserCode(QValue: string);
    function SysUserType(): string;
    procedure SetSysUserType(QValue: string);
    function SysUserTable(): string;
    procedure SetSysUserTable(QValue: string);
    function ZTCode(): string;
    procedure SetZTCode(QValue: string);
    function PlatUserID(): string;
    procedure SetPlatUserID(QValue: string);
    function LastTime(): TDateTime;
    procedure SetLastTime(QValue: TDateTime);
  end;

  TOneTokenManage = class
  private
    FLockObj: TCriticalSection;
    // token容器
    FTokenList: TDictionary<string, IOneTokenItem>;
    FOnLine: integer;
    // 多交没交互失效
    FTimeOutSec: integer;
    FLog: IOneLog;
    // 定时器,定时清理没用的Token
    FTimerThread: TOneTimerThread;
  private
    procedure onTimerWork(Sender: TObject);
  public
    constructor Create(QLog: IOneLog); overload;
    destructor Destroy; override;
  public
    // 获取一个token，交互用的,不包含任何用户信息
    function AddConnectToken(): IOneTokenItem;
    // 添加自已类型的Token
    function AddToken(QTokenItem: IOneTokenItem): boolean;
    // 获取token
    function GetToken(QTokenID: string): IOneTokenItem;
    // 增加一个token，QLoginPlatform 登陆平台，登陆用户, QIsMultiLogin:多点登陆
    function AddLoginToken(QLoginPlatform: string; QLoginCode: string;
      QIsMultiLogin: boolean; var QErrMsg: string): IOneTokenItem;
    // 移除一个token
    procedure RemoveToken(QTokenID: string);

    function CheckToken(QTokenID: string): boolean;
    function CheckSign(QTokenID: string; QUTCTime: string; QSign: string): boolean;

    procedure SaveToken();
    procedure LoadToken();
  public
    property TokenList: TDictionary<string, IOneTokenItem> read FTokenList;
    property OnLine: integer read FOnLine;
  end;

implementation

uses OneCrypto, OneGUID, OneFileHelper;

destructor TOneTokenItem.Destroy;
begin
  inherited Destroy;
end;

function TOneTokenItem.ConnectionID(): string;
begin
  Result := self.FConnectionID;
end;

procedure TOneTokenItem.SetConnectionID(QValue: string);
begin
  self.FConnectionID := QValue;
end;

function TOneTokenItem.TokenID(): string;
begin
  Result := self.FTokenID;
end;

procedure TOneTokenItem.SetTokenID(QValue: string);
begin
  self.FTokenID := QValue;
end;

function TOneTokenItem.PrivateKey(): string;
begin
  Result := self.FPrivateKey;
end;

procedure TOneTokenItem.SetPrivateKey(QValue: string);
begin
  self.FPrivateKey := QValue;
end;

function TOneTokenItem.LoginIP(): string;
begin
  Result := self.FLoginIP;
end;

procedure TOneTokenItem.SetLoginIP(QValue: string);
begin
  self.FLoginIP := QValue;
end;

function TOneTokenItem.LoginMac(): string;
begin
  Result := self.FLoginMac;
end;

procedure TOneTokenItem.SetLoginMac(QValue: string);
begin
  self.FLoginMac := QValue;
end;

function TOneTokenItem.LoginTime(): TDateTime;
begin
  Result := self.FLoginTime;
end;

procedure TOneTokenItem.SetLoginTime(QValue: TDateTime);
begin
  self.FLoginTime := QValue;
end;

function TOneTokenItem.LoginPlatform(): string;
begin
  Result := self.FLoginPlatform;
end;

procedure TOneTokenItem.SetLoginPlatform(QValue: string);
begin
  self.FLoginPlatform := QValue;
end;

function TOneTokenItem.LoginUserCode(): string;
begin
  Result := self.FLoginUserCode;
end;

procedure TOneTokenItem.SetLoginUserCode(QValue: string);
begin
  self.FLoginUserCode := QValue;
end;

function TOneTokenItem.SysUserID(): string;
begin
  Result := self.FSysUserID;
end;

procedure TOneTokenItem.SetSysUserID(QValue: string);
begin
  self.FSysUserID := QValue;
end;

function TOneTokenItem.SysUserName(): string;
begin
  Result := self.FSysUserName;
end;

procedure TOneTokenItem.SetSysUserName(QValue: string);
begin
  self.FSysUserName := QValue;
end;

function TOneTokenItem.SysUserCode(): string;
begin
  Result := self.FSysUserCode;
end;

procedure TOneTokenItem.SetSysUserCode(QValue: string);
begin
  self.FSysUserCode := QValue;
end;

function TOneTokenItem.SysUserType(): string;
begin
  Result := self.FSysUserType;
end;

procedure TOneTokenItem.SetSysUserType(QValue: string);
begin
  self.FSysUserType := QValue;
end;

function TOneTokenItem.SysUserTable(): string;
begin
  Result := self.FSysUserTable;
end;

procedure TOneTokenItem.SetSysUserTable(QValue: string);
begin
  self.FSysUserTable := QValue;
end;

function TOneTokenItem.ZTCode(): string;
begin
  Result := self.FZTCode;
end;

procedure TOneTokenItem.SetZTCode(QValue: string);
begin
  self.FZTCode := QValue;
end;

function TOneTokenItem.PlatUserID(): string;
begin
  Result := self.FPlatUserID;
end;

procedure TOneTokenItem.SetPlatUserID(QValue: string);
begin
  self.FPlatUserID := QValue;
end;

function TOneTokenItem.LastTime(): TDateTime;
begin
  Result := self.FLastTime;
end;

procedure TOneTokenItem.SetLastTime(QValue: TDateTime);
begin
  self.FLastTime := QValue;
end;

// ******* TOneTokenManage **********//
constructor TOneTokenManage.Create(QLog: IOneLog);
begin
  inherited Create;
  FLog := QLog;
  FTimeOutSec := 60 * 30; // 默认30分钟失效无交互
  FLockObj := TCriticalSection.Create;
  FTokenList := TDictionary<string, IOneTokenItem>.Create;
  FTimerThread := TOneTimerThread.Create(self.onTimerWork);
  // 加载内存Token信息
  self.LoadToken;
  // 默认5分钟运作一次
  FTimerThread.IntervalSec := 60 * 5;
  FTimerThread.StartWork;

end;

destructor TOneTokenManage.Destroy;
var
  lTokenItem: IOneTokenItem;
begin
  if FTimerThread <> nil then
    FTimerThread.FreeWork;
  // for lTokenItem in FTokenList.Values do
  // begin
  // TInterfacedObject(lTokenItem).Free;
  // end;
  self.SaveToken;
  FTokenList.Clear;
  FTokenList.Free;
  FLockObj.Free;
  inherited Destroy;
end;

procedure TOneTokenManage.onTimerWork(Sender: TObject);
var
  lTokenItem: IOneTokenItem;
  lNow: TDateTime;
  lSpanSec: integer;
begin
  lNow := Now;
  FLockObj.Enter;
  try
    for lTokenItem in FTokenList.Values do
    begin
      if self.FTimeOutSec > 0 then
      begin
        // 太久没交互,踢除
        if SecondsBetween(lNow, lTokenItem.LastTime) >= self.FTimeOutSec then
        begin
          FTokenList.Remove(lTokenItem.TokenID);
        end;
      end
      else
      begin
        // 无期限的, 6小时没交互也踢除
        if HoursBetween(lNow, lTokenItem.LastTime) >= 6 then
        begin
          FTokenList.Remove(lTokenItem.TokenID);
        end;
      end;
    end;
  finally
    FLockObj.Leave;
  end;
  // 保存Token
  self.SaveToken();
end;

function TOneTokenManage.AddConnectToken(): IOneTokenItem;
var
  lKey: string;
  lTokenItem: TOneTokenItem;
begin
  lKey := OneGUID.GetGUID32;
  FLockObj.Enter;
  try
    lTokenItem := TOneTokenItem.Create;
    lTokenItem.FTokenID := lKey;
    lTokenItem.FPrivateKey := OneGUID.GetGUID32;
    lTokenItem.FLoginIP := '';
    lTokenItem.FLoginTime := Now;
    lTokenItem.FLoginPlatform := '';
    lTokenItem.FLoginUserCode := '';
    lTokenItem.FSysUserID := '';
    lTokenItem.FSysUserName := '';
    lTokenItem.FSysUserType := '';
    lTokenItem.FSysUserTable := '';
    lTokenItem.FLastTime := Now;
    FTokenList.Add(lKey, lTokenItem);
    Result := lTokenItem;
  finally
    FLockObj.Leave;
  end;
end;

function TOneTokenManage.AddToken(QTokenItem: IOneTokenItem): boolean;
begin
  Result := False;
  FLockObj.Enter;
  try
    if self.FTokenList.ContainsKey(QTokenItem.TokenID) then
    begin
      exit;
    end;
    self.FTokenList.Add(QTokenItem.TokenID, QTokenItem);
    Result := True;
  finally
    FLockObj.Leave;
  end;
end;

function TOneTokenManage.GetToken(QTokenID: string): IOneTokenItem;
var
  lTokenItem: IOneTokenItem;
begin
  Result := nil;
  lTokenItem := nil;
  if self.FTokenList.TryGetValue(QTokenID, lTokenItem) then
  begin
    Result := lTokenItem;
  end;
end;

function TOneTokenManage.AddLoginToken(QLoginPlatform: string;
  QLoginCode: string; QIsMultiLogin: boolean; var QErrMsg: string): IOneTokenItem;
var
  lKey: string;
  lTokenItem: IOneTokenItem;
begin
  Result := nil;
  lTokenItem := nil;
  QErrMsg := '';
  lKey := QLoginPlatform + '_' + QLoginCode;
  lKey := OneCrypto.MD5Endcode(lKey);
  FLockObj.Enter;
  try
    if FTokenList.ContainsKey(lKey) then
    begin
      FTokenList.TryGetValue(lKey, lTokenItem);
      if QIsMultiLogin and (lTokenItem <> nil) then
      begin
        lTokenItem.SetLoginTime(Now);
        Result := lTokenItem;
        exit;
      end;
      if lTokenItem <> nil then
      begin
        lTokenItem := nil;
      end;
      FTokenList.Remove(lKey);
    end;
    lTokenItem := TOneTokenItem.Create;
    lTokenItem.SetTokenID(lKey);
    lTokenItem.SetPrivateKey(OneGUID.GetGUID32);
    lTokenItem.SetLoginIP('');
    lTokenItem.SetLoginTime(Now);
    lTokenItem.SetLoginPlatform(QLoginPlatform);
    lTokenItem.SetLoginUserCode(QLoginCode);
    lTokenItem.SetSysUserID('');
    lTokenItem.SetSysUserName('');
    lTokenItem.SetSysUserType('');
    lTokenItem.SetSysUserTable('');
    lTokenItem.SetLastTime(Now);
    FTokenList.Add(lKey, lTokenItem);
    Result := lTokenItem;
  finally
    FLockObj.Leave;
  end;
end;

procedure TOneTokenManage.RemoveToken(QTokenID: string);
begin
  FLockObj.Enter;
  try
    FTokenList.Remove(QTokenID);
  finally
    FLockObj.Leave;
  end;
end;

function TOneTokenManage.CheckToken(QTokenID: string): boolean;
var
  lTokenItem: IOneTokenItem;
  lNow: TDateTime;
  lSub: double;
begin
  Result := False;
  if FTokenList.TryGetValue(QTokenID, lTokenItem) then
  begin

    lNow := Now;
    if FTimeOutSec > 0 then
    begin
      // 有设置过期时间
      lSub := SecondSpan(lNow, lTokenItem.LastTime);
      // token失效
      if lSub > FTimeOutSec then
      begin
        self.RemoveToken(lTokenItem.TokenID);
        lTokenItem := nil;
        exit;
      end;
    end;
    // 合法刷新最后交互时间,保证TOKEN有效性
    lTokenItem.SetLastTime(lNow);
    Result := True;
  end;
end;

function TOneTokenManage.CheckSign(QTokenID: string; QUTCTime: string;
  QSign: string): boolean;
var
  lTokenItem: IOneTokenItem;
  lNow: TDateTime;
  tempSign: string;
begin
  Result := False;
  lNow := Now;
  if not FTokenList.TryGetValue(QTokenID, lTokenItem) then
    exit;
  tempSign := QTokenID + QUTCTime + lTokenItem.PrivateKey;
  tempSign := OneCrypto.MD5Endcode(tempSign);
  if tempSign.ToLower = QSign.ToLower then
  begin
    lTokenItem.SetLastTime(lNow);
    Result := True;
  end;
end;

procedure TOneTokenManage.SaveToken();
var
  lDataSet: TBufDataSet;
  lFileName: string;
  lTokenItem: IOneTokenItem;
begin
  lDataSet := TBufDataSet.Create(nil);
  try
    // 创建字段
    lDataSet.FieldDefs.Add('FConnectionID', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FTokenID', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FPrivateKey', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FLoginIP', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FLoginMac', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FLoginTime', ftDateTime, 0, False);
    lDataSet.FieldDefs.Add('FLoginPlatform', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FLoginUserCode', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FSysUserID', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FSysUserName', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FZTCode', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FPlatUserID', ftWidestring, 50, False);
    lDataSet.FieldDefs.Add('FLastTime', ftDateTime, 0, False);
    lDataSet.CreateDataset;
    for lTokenItem in FTokenList.Values do
    begin
      lDataSet.Append;
      lDataSet.FieldByName('FConnectionID').AsString := lTokenItem.ConnectionID;
      lDataSet.FieldByName('FTokenID').AsString := lTokenItem.TokenID;
      lDataSet.FieldByName('FPrivateKey').AsString := lTokenItem.PrivateKey;
      lDataSet.FieldByName('FLoginIP').AsString := lTokenItem.LoginIP;
      lDataSet.FieldByName('FLoginMac').AsString := lTokenItem.LoginMac;
      lDataSet.FieldByName('FLoginTime').AsDateTime := lTokenItem.LoginTime;
      lDataSet.FieldByName('FLoginPlatform').AsString := lTokenItem.LoginPlatform;
      lDataSet.FieldByName('FLoginUserCode').AsString := lTokenItem.LoginUserCode;
      lDataSet.FieldByName('FSysUserID').AsString := lTokenItem.SysUserID;
      lDataSet.FieldByName('FSysUserName').AsString := lTokenItem.SysUserName;
      lDataSet.FieldByName('FZTCode').AsString := lTokenItem.ZTCode;
      lDataSet.FieldByName('FPlatUserID').AsString := lTokenItem.PlatUserID;
      lDataSet.FieldByName('FLastTime').AsDateTime := lTokenItem.LastTime;
      lDataSet.Post;
    end;
    lFileName := OneFileHelper.CombineExeRunPath('OnePlatform\OneToken');
    if not DirectoryExists(lFileName) then
      ForceDirectories(lFileName);
    lFileName := OneFileHelper.CombineExeRunPath('OnePlatform\OneToken\TokenStore.data');
    lDataSet.SaveToFile(lFileName, TDataPacketFormat.dfBinary);
  finally
    lDataSet.Close;
    lDataSet.Free;
  end;
end;

procedure TOneTokenManage.LoadToken();
var
  lDataSet: TBufDataSet;
  lFileName: string;
  lTokenItem: IOneTokenItem;
begin
  lFileName := OneFileHelper.CombineExeRunPath('OnePlatform\OneToken\TokenStore.data');
  if not FileExists(lFileName) then
    exit;
  lDataSet := TBufDataSet.Create(nil);
  try
    lFileName := OneFileHelper.CombineExeRunPath('OnePlatform\OneToken\TokenStore.data');
    lDataSet.LoadFromFile(lFileName, TDataPacketFormat.dfBinary);
    if not lDataSet.Active then
      exit;
    if lDataSet.RecordCount = 0 then
      exit;
    lDataSet.First;
    while not lDataSet.EOF do
    begin
      lTokenItem := TOneTokenItem.Create;
      lTokenItem.SetConnectionID(lDataSet.FieldByName('FConnectionID').AsString);
      lTokenItem.SetTokenID(lDataSet.FieldByName('FTokenID').AsString);
      lTokenItem.SetPrivateKey(lDataSet.FieldByName('FPrivateKey').AsString);
      lTokenItem.SetLoginIP(lDataSet.FieldByName('FLoginIP').AsString);
      lTokenItem.SetLoginMac(lDataSet.FieldByName('FLoginMac').AsString);
      lTokenItem.SetLoginTime(lDataSet.FieldByName('FLoginTime').AsDateTime);
      lTokenItem.SetLoginPlatform(lDataSet.FieldByName('FLoginPlatform').AsString);
      lTokenItem.SetLoginUserCode(lDataSet.FieldByName('FLoginUserCode').AsString);
      lTokenItem.SetSysUserID(lDataSet.FieldByName('FSysUserID').AsString);
      lTokenItem.SetSysUserName(lDataSet.FieldByName('FSysUserName').AsString);
      lTokenItem.SetZTCode(lDataSet.FieldByName('FZTCode').AsString);
      lTokenItem.SetPlatUserID(lDataSet.FieldByName('FPlatUserID').AsString);
      lTokenItem.SetLastTime(lDataSet.FieldByName('FLastTime').AsDateTime);
      if not self.TokenList.ContainsKey(lTokenItem.TokenID) then
      begin
        self.TokenList.Add(lTokenItem.TokenID, lTokenItem);
      end;
      lDataSet.Next;
    end;
  finally
    lDataSet.Close;
    lDataSet.Free;
  end;
end;

end.
