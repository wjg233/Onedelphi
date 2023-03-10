unit OneZTManage;

{$mode DELPHI}{$H+}

interface

uses
  Generics.Collections, SyncObjs, DB, SysUtils, SQLDB,
  Classes, StrUtils, Variants, TypInfo,
  OneDataInfo, OneThread, OneGUID, OneFileHelper,
  OneStreamString, OneILog, DateUtils, BufDataset, fpjson,jsonparser,
  Zipper, zstream, SQLDBLib, OneSerialization, RegExpr, OneDataJson;

const
  Driver_MSSQLServer = 'MSSQLServer';
  Driver_MySQL = 'MySQL';
  Driver_Oracle = 'Oracle';
  Driver_PostgreSQL = 'PostgreSQL';
  Driver_SQLite3 = 'SQLite3';
  Driver_Sybase = 'Sybase';
  Driver_Firebird = 'Firebird';

type
  TOneZTSet = class;
  TOneZTMangeSet = class;
  TOneZTItem = class;
  TOneZTPool = class;
  TOneZTManage = class;
  TOneFDException = class;
  emZTKeepMode = (keepTran, keepTempData);

  TSQLInfo = record
    FDriver: string;
    FDriverVersion: string;
    FPageIndex: integer;
    FPageSize: integer;
    FSQL: string;
    FOrderByLine: integer;
    FOrderSQL: string;
    FPageField: string;
    FErrMsg: string;
  end;

  TFDConnection = class(TSQLConnector)

  end;

  TFDTransaction = class(TSQLTransaction)
  private
    FIsInTran: boolean;
  public
    constructor Create(AOwner: TComponent); override;
    procedure TranStart;
    procedure TranCommit;
    procedure TranRollback;
  public
    property IsInTran: boolean read FIsInTran write FIsInTran;
  end;

  TFDQuery = class(TSQLQuery)
  private
    FTableName: string;
    FKeyFields: string;
  public
    property TableName: string read FTableName write FTableName;
    property KeyFields: string read FKeyFields write FKeyFields;
  end;

  TFDScript = class(TSQLScript)

  end;

  TFDStoredProc = class(TSQLQuery)
  private
    FStoredProcName: string;
    FPackageName: string;
  public
    property StoredProcName: string read FStoredProcName write FStoredProcName;
    property PackageName: string read FPackageName write FPackageName;
  end;

  TFDMemtable = class(TBufDataset)

  end;

  TFDParam = class(TParams)

  end;

  TOneFDException = class(TObject)
  public
    FErrmsg: string;
  end;

  TZTKeepInfo = class
  private
    FKeepID: string;
    FKeepMode: emZTKeepMode;
    FKeepSec: integer;
    FLastTime: TDateTime;
  end;

  // ????????????
  TOneZTSet = class
  private
    FZTCode: string; // ????????????
    FZTCaption: string; // ????????????
    FInitPoolCount: integer; // ????????????????????????
    FMaxPoolCount: integer; // ?????????????????????
    FConnectionStr: string; // ???????????????
    FIsEnable: boolean; // ????????????
    FIsMain: boolean; // ???????????????
    FPhyDriver: string; // ????????????
    FDBType: string;
    FDBVersion: string;
    FDBHostName: string;
    FDBCharSet: string;
    FDBHostPort: integer;
    FDBName: string;
    FDBUserName: string;
    FDBUserPass: string;
    FDBKeepConnect: boolean;
    FDBOtherParams: string;
  published
    property ZTCode: string read FZTCode write FZTCode;
    property ZTCaption: string read FZTCaption write FZTCaption;
    property InitPoolCount: integer read FInitPoolCount write FInitPoolCount;
    property MaxPoolCount: integer read FMaxPoolCount write FMaxPoolCount;
    property ConnectionStr: string read FConnectionStr write FConnectionStr;
    property IsEnable: boolean read FIsEnable write FIsEnable;
    property IsMain: boolean read FIsMain write FIsMain;
    property PhyDriver: string read FPhyDriver write FPhyDriver;
    property DBType: string read FDBType write FDBType;
    property DBVersion: string read FDBVersion write FDBVersion;
    property DBHostName: string read FDBHostName write FDBHostName;
    property DBCharSet: string read FDBCharSet write FDBCharSet;
    property DBHostPort: integer read FDBHostPort write FDBHostPort;
    property DBName: string read FDBName write FDBName;
    property DBUserName: string read FDBUserName write FDBUserName;
    property DBUserPass: string read FDBUserPass write FDBUserPass;
    property DBKeepConnect: boolean read FDBKeepConnect write FDBKeepConnect;
    property DBOtherParams: string read FDBOtherParams write FDBOtherParams;
  end;

  TOneZTMangeSet = class
  private
    FAutoWork: boolean;
    FZTSetList: TList<TOneZTSet>;
  public
    constructor Create();
    destructor Destroy; override;
  published
    property AutoWork: boolean read FAutoWork write FAutoWork;
    property ZTSetList: TList<TOneZTSet> read FZTSetList write FZTSetList;
  end;

  { ???????????? }
  TOneZTItem = class(TObject)
  private
    FCreateID: string; // ??????????????????

    FOwnerZTPool: TOneZTPool;
    FIsWorking: boolean; // ???????????????
    // FD??????,????????????????????????????????????????????????????????????????????????
    FDConnection: TFDConnection;
    FDTransaction: TFDTransaction;
    FDQuery: TFDQuery;
    FDScript: TFDScript;
    FDStoredProc: TFDStoredProc;
    // ????????????????????????
    FTempStream: TMemoryStream;
    FException: TOneFDException;

    FCharacterSet: string;
    // ???????????????????????????????????????
    FCustTran: boolean;
    // ??????????????????,???????????????
    // -1?????????,????????????????????????????????????????????????????????????
    // 0 ????????????????????????30???????????????30????????????????????????,?????????????????????
    // >0  ????????????????????????>0???????????????>0????????????????????????,?????????????????????
    FCustTranMaxSpanSec: integer;
    // ??????????????????
    FLastTime: TDateTime;
    FZTSet: TOneZTSet;
  private
    // ???????????????????????? FDConnection
    function GetADConnection: TFDConnection;
    // ???????????????????????? FDTransaction??????connection????????? FDConnection
    function GetADTransaction: TFDTransaction;
    // ????????????Query?????? ??????connection????????? FDConnection
    function GetQuery: TFDQuery;
    // ????????????Script???????????? ??????connection????????? FDConnection
    function GetScript: TFDScript;
    // ????????????Stored????????????????????? ??????connection????????? FDConnection
    function GetStoredProc: TFDStoredProc;
    function GetTempStream: TMemoryStream;
    procedure FDQueryError(ASender, AInitiator: TObject; var AException: Exception);
    procedure FDScriptError(ASender, AInitiator: TObject; var AException: Exception);
  public
    constructor Create(AOwner: TOneZTPool; QZTSet: TOneZTSet); overload;
    destructor Destroy; override;
    procedure UnLockWork();
  public
    property ADConnection: TFDConnection read FDConnection;
    property ADTransaction: TFDTransaction read GetADTransaction;
    property ADQuery: TFDQuery read GetQuery;
    property ADScript: TFDScript read GetScript;
    property ADStoredProc: TFDStoredProc read GetStoredProc;
    property IsWorking: boolean read FIsWorking write FIsWorking;
    property DataStream: TMemoryStream read GetTempStream;
    property ZTSet: TOneZTSet read GetTempStream;
  end;

  { ??????????????? }
  TOneZTPool = class(TObject)
  private
    FZTManage: TOneZTManage;
    FZTCode: string; // ????????????
    FInitPoolCount: integer; // ??????????????????
    FMaxPoolCount: integer; // ???????????????
    FPoolCreateCount: integer; // ??????????????????
    FPoolWorkCount: integer; // ?????????????????????

    FPhyDriver: string; // ???????????????
    FConnectionStr: string; // ???????????????
    FStop: boolean; // ????????????
    FLockObj: TCriticalSection; // ???
    FZTItems: TList<TOneZTItem>; // ?????????
    FZTSet: TOneZTSet;
  public
    // ???????????????
    constructor Create(QZTManage: TOneZTManage; QZTSet: TOneZTSet); overload;
    destructor Destroy; override;
    // ?????????????????????????????????
    function LockZTItem(var QErrMsg: string): TOneZTItem;
    procedure UnLockWorkCount();
  public

  public
    property Stop: boolean read FStop write FStop;
    property ZTCode: string read FZTCode write FZTCode;
    property InitPoolCount: integer read FInitPoolCount; // ??????????????????
    property MaxPoolCount: integer read FMaxPoolCount; // ???????????????
    property PoolCreateCount: integer read FPoolCreateCount; // ??????????????????
    property PoolWorkCount: integer read FPoolWorkCount; // ?????????????????????
  end;

  { ????????????-??????hase?????? }
  TOneZTManage = class(TObject)
  private
    FZTMain: string;
    FStop: boolean;
    FZTPools: TDictionary<string, TOneZTPool>;
    FTranZTItemList: TDictionary<string, TOneZTItem>;
    FLockObject: TCriticalSection;
    FLog: IOneLog;
    FKeepList: TList<TZTKeepInfo>;
    // ??????????????????,??????????????????
    FTimerThread: TOneTimerThread;
    //??????
    FLibrarys: TDictionary<string, TSQLDBLibraryLoader>;
  private
    procedure onTimerWork(Sender: TObject);
    procedure InitPhyDriver(QDriverName: string);
    procedure BuildStoredSQL(QPhyDirver: string; QOpenData: TOneDataOpen);
  public
    constructor Create(QOneLog: IOneLog); overload;
    destructor Destroy; override;
    function StarWork(QZTSetList: TList<TOneZTSet>; var QErrMsg: string): boolean;
  public
    // ????????????????????????
    function StopZT(QZTCode: string; QStop: boolean; var QErrMsg: string): boolean;
    // ??????????????????
    function LockZTItem(QZTCode: string; var QErrMsg: string): TOneZTItem;
    // ************ ????????????????????????,?????????????????????,???????????????,????????????***********//
    // ??????????????????,????????????????????????
    function LockTranItem(QZTCode: string; QMaxSpanSec: integer; var QErrMsg: string): string;
    // ??????????????????,????????????????????????
    function UnLockTranItem(QTranID: string; var QErrMsg: string): boolean;
    // ??????????????????,????????????????????????
    function StartTranItem(QTranID: string; var QErrMsg: string): boolean;
    // ??????????????????,????????????????????????
    function CommitTranItem(QTranID: string; var QErrMsg: string): boolean;
    // ??????????????????,????????????????????????
    function RollbackTranItem(QTranID: string; var QErrMsg: string): boolean;
    // ?????????????????????????????????
    function GetTranItem(QTranID: string; var QErrMsg: string): TOneZTItem;
    // ?????????????????????????????????
    // **********************************************//
    function InitZTPool(QZTSet: TOneZTSet; var QErrMsg: string): boolean;
    function HaveZT(QZTCode: string): boolean;
  public
    function GetZTMain: string;
    // ????????????
    function OpenData(QOpenData: TOneDataOpen; QOneDataResult: TOneDataResult): boolean;
      overload;
    // IsServer???????????????????????????????????????
    function OpenDatas(QOpenDatas: TList<TOneDataOpen>; var QOneDataResult: TOneDataResult): boolean;
    // ????????????
    function SaveDatas(QSaveDMLDatas: TList<TOneDataSaveDML>; var QOneDataResult: TOneDataResult): boolean;
    // ??????????????????
    function ExecStored(QOpenData: TOneDataOpen; var QOneDataResult: TOneDataResult): boolean;
  public
    // ???????????????Orm??????
    function OpenData(QOpenData: TOneDataOpen; QParams: array of variant; var QErrMsg: string): TFDMemtable; overload;
    function ExecSQL(QDataSaveDML: TOneDataSaveDML; QParams: array of variant; var QErrMsg: string): integer;
  public
    property ZTMain: string read FZTMain write FZTMain;
    property ZTPools: TDictionary<string, TOneZTPool> read FZTPools write FZTPools;
  end;

// ??? Order by SQL
function ClearOrderBySQL(QSQL: string): string;
//????????????SQL
function SetSQLInfo(var QSQLInfo: TSQLInfo): boolean;
procedure InitSQLInfo(var QSQLInfo: TSQLInfo);
//??????????????????

var
  Var_ADOZTMgr: TOneZTManage;
  // ????????????
  Var_MSSQLDriverLink: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink4_0: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink4_1: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink5_0: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink5_1: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink5_5: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink5_6: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink5_7: TSQLDBLibraryLoader = nil;
  Var_MySQLDriverLink8_0: TSQLDBLibraryLoader = nil;
  Var_OracleDriverLink: TSQLDBLibraryLoader = nil;
  var_PGDriverLink: TSQLDBLibraryLoader = nil;
  var_FireBirdDriverLinK: TSQLDBLibraryLoader = nil;
  var_FireBirdDriverLinKB: TSQLDBLibraryLoader = nil;
  var_SQLiteDriverLinK: TSQLDBLibraryLoader = nil;
  var_ASADriverLink: TSQLDBLibraryLoader = nil;
  var_ODBCDriverLink: TSQLDBLibraryLoader = nil;
  var_MSAccDriverLink: TSQLDBLibraryLoader = nil;

implementation

uses OneStopwatch;

constructor TFDTransaction.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  self.Options := [stoUseImplicit];
  self.FIsInTran := False;
end;

procedure TFDTransaction.TranStart;
begin
  if self.FIsInTran then
    exit;
  if self.Active then
  begin
    self.FIsInTran := True;
    exit;
  end;
  self.StartTransaction;
  self.FIsInTran := True;
end;

procedure TFDTransaction.TranCommit;
begin
  if self.FIsInTran then
  begin
    self.CommitRetaining;
    self.FIsInTran := False;
  end;
end;

procedure TFDTransaction.TranRollback;
begin
  if self.FIsInTran then
  begin
    self.RollbackRetaining;
    self.FIsInTran := False;
  end;
end;

constructor TOneZTMangeSet.Create();
begin
  inherited Create;
  FZTSetList := TList<TOneZTSet>.Create;
  //?????????RTTI???
  OneSerialization.AddListClass(TList<TOneZTSet>, TOneZTSet, nil);
end;

destructor TOneZTMangeSet.Destroy;
var
  i: integer;
begin
  for i := 0 to FZTSetList.Count - 1 do
  begin
    FZTSetList[i].Free;
  end;
  FZTSetList.Clear;
  FZTSetList.Free;
  inherited Destroy;
end;


constructor TOneZTItem.Create(AOwner: TOneZTPool; QZTSet: TOneZTSet);
var
  LSetList: TStringList;
  i, iPortIndex: integer;
begin
  inherited Create;
  FCreateID := OneGUID.GetGUID32();
  self.FCustTran := False;
  self.FLastTime := Now;
  self.FOwnerZTPool := AOwner;
  self.FZTSet := QZTSet;
  { ????????????????????? }
  FDConnection := TFDConnection.Create(nil);
  LSetList := TStringList.Create();
  try
    LSetList.LineBreak := ';';
    LSetList.Text := QZTSet.DBOtherParams;
    FDConnection.LoginPrompt := False;
    //???????????????
    FDConnection.ConnectorType := QZTSet.PhyDriver;
    //???????????????
    FDConnection.CharSet := QZTSet.DBCharSet;
    //???????????????
    FDConnection.HostName := QZTSet.DBHostName;
    //???????????????
    FDConnection.DatabaseName := QZTSet.DBName;
    //???????????????
    FDConnection.UserName := QZTSet.DBUserName;
    //???????????????
    FDConnection.Password := QZTSet.DBUserPass;
    //???????????????
    FDConnection.KeepConnection := QZTSet.DBKeepConnect;

    if QZTSet.DBHostPort > 0 then
    begin
      FDConnection.params.Values['Port'] := QZTSet.DBHostPort.ToString;
    end
    else
    if FDConnection.params.IndexOfName('Port') > -1 then
    begin
      iPortIndex := FDConnection.params.IndexOfName('Port');
      FDConnection.params.Delete(iPortIndex);
    end;
    for i := 0 to LSetList.Count - 1 do
    begin
      FDConnection.Params.Add(LSetList[i]);
    end;
    //????????????DLL??????
    self.FOwnerZTPool.FZTManage.InitPhyDriver(FDConnection.ConnectorType);
    //FDConnection.LIB := InitPhyDriver(FDConnection.Protocol);
  finally
    LSetList.Free;
  end;

  FDTransaction := TFDTransaction.Create(nil);
  // ?????????????????????
  //FCharacterSet := FDConnection.Params.Values['CharacterSet'];
  //FCharacterSet := FCharacterSet.ToLower;
  FDQuery := TFDQuery.Create(nil);
  FDStoredProc := TFDStoredProc.Create(nil);

  // FDStoredProc.FetchOptions.Items := [fiBlobs,fiDetails,fiMeta];
  FTempStream := TMemoryStream.Create;

  FException := TOneFDException.Create;
end;

destructor TOneZTItem.Destroy;
begin
  FOwnerZTPool := nil;
  if FDTransaction <> nil then
    FDTransaction.Free;
  if FDQuery <> nil then
    FDQuery.Free;
  if FDStoredProc <> nil then
    FDStoredProc.Free;
  if FDConnection <> nil then
  begin
    FDConnection.Connected := False;
    FDConnection.Free;
  end;
  if FTempStream <> nil then
  begin
    FTempStream.Clear;
    FTempStream.Free;
  end;
  FException.Free;
  inherited Destroy;
end;

function TOneZTItem.GetADConnection: TFDConnection;
begin
  Result := nil;
  if not FDConnection.Connected then
    FDConnection.Connected := True;
  if FDConnection.Connected then
    Result := FDConnection;
end;

function TOneZTItem.GetADTransaction: TFDTransaction;
begin
  Result := FDTransaction;
  FDTransaction.DataBase := FDConnection;
end;

function TOneZTItem.GetQuery: TFDQuery;
begin
  self.GetADConnection;
  Result := FDQuery;
  if FDQuery.Active then
  begin
    FDQuery.Close;
  end;
  FDQuery.SQL.Clear;
  FDQuery.Params.Clear;
  FDTransaction.DataBase := FDConnection;
  FDQuery.DataBase := FDConnection;
  FDQuery.Transaction := FDTransaction;
end;

function TOneZTItem.GetScript: TFDScript;
begin
  Result := FDScript;
  FDTransaction.DataBase := FDConnection;
  FDScript.DataBase := FDConnection;
  FDScript.Transaction := FDTransaction;
  FDTransaction.CloseDataSets;
end;

function TOneZTItem.GetStoredProc: TFDStoredProc;
begin
  Result := nil;
  if (FDStoredProc <> nil) then
  begin
    FDStoredProc.Free;
    FDStoredProc := nil;
  end;
  // ?????????????????????
  FDStoredProc := TFDStoredProc.Create(nil);
  if FDStoredProc.Active then
    FDStoredProc.Close;
  FDStoredProc.Params.Clear;
  FDTransaction.DataBase := FDConnection;
  FDStoredProc.DataBase := FDConnection;
  FDStoredProc.Transaction := FDTransaction;
  Result := FDStoredProc;
end;

function TOneZTItem.GetTempStream: TMemoryStream;
begin
  FTempStream.Clear;
  FTempStream.Position := 0;
  Result := FTempStream;
end;

procedure TOneZTItem.FDQueryError(ASender, AInitiator: TObject; var AException: Exception);
begin
  if (AException <> nil) and (AException.Message <> '') then
  begin
    self.FException.FErrmsg := AException.Message;
  end;
end;

procedure TOneZTItem.FDScriptError(ASender, AInitiator: TObject; var AException: Exception);
begin

end;

procedure TOneZTItem.UnLockWork();
begin
  // ??????????????????
  // UnLockTranItem??????????????????????????????
  if self.FCustTran then
    exit;
  // ???????????????

  // ????????????????????????,??????
  if FDTransaction.IsInTran then
  begin
    FDTransaction.TranRollback;
  end;
  if FDQuery.Active then
  begin
    FDQuery.Close;
  end;
  FDQuery.SQL.Clear;
  FDQuery.Params.Clear;

  // ????????????
  if FDStoredProc.Active then
  begin
    FDStoredProc.Close;
  end;
  if FDStoredProc.Params.Count > 0 then  FDStoredProc.Params.Clear;
  FDStoredProc.DataBase := nil;
  if FTempStream <> nil then
  begin
    FTempStream.Position := 0;
    FTempStream.Clear;
  end;
  // ??????1800????????????
  FCustTranMaxSpanSec := 30 * 60;
  FIsWorking := False;
  self.FOwnerZTPool.UnLockWorkCount();
end;

// ?????????????????????
constructor TOneZTPool.Create(QZTManage: TOneZTManage; QZTSet: TOneZTSet);
var
  i: integer;
  lZTItem: TOneZTItem;
begin
  inherited Create;
  self.FZTManage := QZTManage;
  if QZTSet.InitPoolCount <= 0 then
    QZTSet.InitPoolCount := 5;
  if QZTSet.MaxPoolCount <= 0 then
    QZTSet.MaxPoolCount := 10;
  FZTSet := QZTSet;
  FZTCode := QZTSet.ZTCode;
  FInitPoolCount := QZTSet.InitPoolCount;
  FMaxPoolCount := QZTSet.MaxPoolCount;
  FPoolCreateCount := 0; // ??????????????????
  FPoolWorkCount := 0;
  // ?????????????????????
  FPhyDriver := QZTSet.PhyDriver;
  FConnectionStr := QZTSet.ConnectionStr;
  self.FZTItems := TList<TOneZTItem>.Create();
  FLockObj := TCriticalSection.Create;
  for i := 0 to FInitPoolCount - 1 do
  begin
    lZTItem := TOneZTItem.Create(self, QZTSet);
    lZTItem.FLastTime := Now;
    self.FZTItems.Add(lZTItem);
    self.FPoolCreateCount := self.FPoolCreateCount + 1;
  end;
end;

destructor TOneZTPool.Destroy;
var
  i: integer;
begin
  if FLockObj <> nil then
    FLockObj.Free;
  if self.FZTItems <> nil then
  begin
    for i := 0 to FZTItems.Count - 1 do
    begin
      FZTItems[i].Free;
    end;
    FZTItems.Clear;
    FZTItems.Free;
  end;
  inherited Destroy;
end;

function TOneZTPool.LockZTItem(var QErrMsg: string): TOneZTItem;
var
  i: integer;
  lZTItem: TOneZTItem;
begin
  Result := nil;
  lZTItem := nil;
  QErrMsg := '';
  FLockObj.Enter;
  try
    if self.FPoolWorkCount >= self.FMaxPoolCount then
    begin
      QErrMsg := '?????????[' + self.FZTCode + ']????????????????????????[' + FPoolWorkCount.ToString() + ']';
      exit;
    end;
    // ???????????????????????????
    for i := 0 to self.FZTItems.Count - 1 do
    begin
      if self.FZTItems[i].IsWorking then
        continue;
      lZTItem := self.FZTItems[i];
      // ??????????????????
      break;
    end;
    if lZTItem = nil then
    begin
      // ????????????????????????????????????
      lZTItem := TOneZTItem.Create(self, self.FZTSet);
      // ???????????????
      self.FZTItems.Add(lZTItem);
      self.FPoolCreateCount := self.FPoolCreateCount + 1;
    end;
    lZTItem.FLastTime := Now;
    // ????????????1
    lZTItem.IsWorking := True;
    self.FPoolWorkCount := self.FPoolWorkCount + 1;
    Result := lZTItem;
  finally
    FLockObj.Leave;
  end;
end;

procedure TOneZTPool.UnLockWorkCount();
begin
  FLockObj.Enter;
  try
    self.FPoolWorkCount := self.FPoolWorkCount - 1;
  finally
    FLockObj.Leave;
  end;
end;

constructor TOneZTManage.Create(QOneLog: IOneLog);
begin
  inherited Create;
  self.FLog := QOneLog;
  FZTPools := TDictionary<string, TOneZTPool>.Create;
  FTranZTItemList := TDictionary<string, TOneZTItem>.Create;
  FLockObject := TCriticalSection.Create;
  FKeepList := TList<TZTKeepInfo>.Create;
  FTimerThread := TOneTimerThread.Create(self.onTimerWork);
  FLibrarys := TDictionary<string, TSQLDBLibraryLoader>.Create;
end;

destructor TOneZTManage.Destroy;
var
  i: integer;
  lZTPool: TOneZTPool;
  lZTItem: TOneZTItem;
  lLib: TSQLDBLibraryLoader;
begin
  if FTimerThread <> nil then
    FTimerThread.FreeWork;
  // ???????????????
  for lZTItem in FTranZTItemList.Values do
  begin
    if lZTItem.ADTransaction.IsInTran then
    begin
      lZTItem.ADTransaction.TranRollback;
    end;
  end;
  FTranZTItemList.Clear;
  FTranZTItemList.Free;
  // ???????????????
  for lZTPool in FZTPools.Values do
  begin
    lZTPool.Free;
  end;
  FZTPools.Clear;
  FZTPools.Free;
  FLockObject.Free;
  for i := 0 to FKeepList.Count - 1 do
  begin
    FKeepList[i].Free;
  end;
  FKeepList.Clear;
  FKeepList.Free;
  for lLib in FLibrarys.values do
  begin
    lLib.Free;
  end;
  FLibrarys.Clear;
  FLibrarys.Free;
  inherited Destroy;
end;

procedure TOneZTManage.onTimerWork(Sender: TObject);
var
  lZTItem: TOneZTItem;
  lNow: TDateTime;
  lSpanSec: integer;
begin
  FLockObject.Enter;
  try
    lNow := Now;
    // ???????????????
    for lZTItem in FTranZTItemList.Values do
    begin
      if lZTItem.FCustTranMaxSpanSec < 0 then
        continue;

      if lZTItem.FCustTranMaxSpanSec = 0 then
      begin
        lZTItem.FCustTranMaxSpanSec := 30 * 60;
      end;
      // ???????????????,??????????????????
      if SecondsBetween(lNow, lZTItem.FLastTime) >= lZTItem.FCustTranMaxSpanSec then
      begin
        if lZTItem.ADTransaction.IsInTran then
        begin
          // ??????
          lZTItem.ADTransaction.TranRollback;
        end;
        lZTItem.FCustTran := False;
        lZTItem.UnLockWork;
        FTranZTItemList.Remove(lZTItem.FCreateID);
      end;
    end;
  finally
    FLockObject.leave;
  end;
end;

function TOneZTManage.GetZTMain: string;
begin
  Result := FZTMain;
end;

function TOneZTManage.LockZTItem(QZTCode: string; var QErrMsg: string): TOneZTItem;
var
  lZTPool: TOneZTPool;
begin
  Result := nil;
  QErrMsg := '';
  FLockObject.Enter;
  try
    if FStop then
    begin
      QErrMsg := '????????????????????????????????????????????????!!!';
      exit;
    end;
    if QZTCode = '' then
    begin
      QZTCode := self.ZTMain;
    end;
    if QZTCode = '' then
    begin
      QErrMsg := '????????????????????????????????????????????????';
      exit;
    end;
    if FZTPools.TryGetValue(QZTCode.ToUpper, lZTPool) then
    begin
      if lZTPool.Stop then
      begin
        QErrMsg := '??????[' + QZTCode + ']???????????????????????????????????????';
        exit;
      end;
      Result := lZTPool.LockZTItem(QErrMsg);
      if Result = nil then
      begin
        exit;
      end;
    end
    else
    begin
      QErrMsg := '?????????????????????????????????[' + QZTCode + ']';
    end;
  finally
    FLockObject.leave;
  end;
  if Result <> nil then
  begin
    if not Result.ADConnection.Connected then
    begin
      // ???????????????????????????
      Result.ADConnection.Connected := False;
      Result.ADConnection.Connected := True;
    end;
  end;
end;

function TOneZTManage.LockTranItem(QZTCode: string; QMaxSpanSec: integer; var QErrMsg: string): string;
var
  lFireZTPool: TOneZTPool;
  lZTItem: TOneZTItem;
  lStartTranID: string;
begin
  Result := '';
  QErrMsg := '';
  lZTItem := nil;
  lZTItem := self.LockZTItem(QZTCode, QErrMsg);
  if lZTItem = nil then
  begin
    exit;
  end;
  FLockObject.Enter;
  try
    lZTItem.FCustTran := True;
    lZTItem.FCustTranMaxSpanSec := QMaxSpanSec;
    self.FTranZTItemList.Add(lZTItem.FCreateID, lZTItem);
    Result := lZTItem.FCreateID;
  finally
    FLockObject.leave;
  end;
end;

function TOneZTManage.UnLockTranItem(QTranID: string; var QErrMsg: string): boolean;
var
  lZTItem: TOneZTItem;
begin
  Result := False;
  QErrMsg := '';
  FLockObject.Enter;
  try
    if FTranZTItemList.TryGetValue(QTranID, lZTItem) then
    begin
      if lZTItem.ADTransaction.IsInTran then
      begin
        lZTItem.ADTransaction.TranRollback;
        lZTItem.FLastTime := Now;
      end;
      lZTItem.FCustTran := False;
      lZTItem.UnLockWork;
      Result := True;
    end
    else
    begin
      QErrMsg := '?????????????????????????????????';
      Result := False;
    end;
  finally
    FLockObject.leave;
    FTranZTItemList.Remove(QTranID);

  end;

end;

function TOneZTManage.GetTranItem(QTranID: string; var QErrMsg: string): TOneZTItem;
var
  lZTItem: TOneZTItem;
begin
  Result := nil;
  QErrMsg := '';
  FLockObject.Enter;
  try
    if FTranZTItemList.TryGetValue(QTranID, lZTItem) then
    begin
      Result := lZTItem;
      Result.FLastTime := Now;
    end
    else
    begin
      QErrMsg := '?????????????????????????????????';
    end;
  finally
    FLockObject.leave;
  end;
end;

// ???????????????????????????????????????,????????????????????????
function TOneZTManage.StartTranItem(QTranID: string; var QErrMsg: string): boolean;
var
  lZTItem: TOneZTItem;
begin
  Result := False;
  QErrMsg := '';
  FLockObject.Enter;
  try
    if FTranZTItemList.TryGetValue(QTranID, lZTItem) then
    begin
      lZTItem.ADTransaction.TranStart;
      lZTItem.FLastTime := Now;
      Result := True;
    end
    else
    begin
      QErrMsg := '?????????????????????????????????';
      Result := False;
    end;
  finally
    FLockObject.leave;
  end;
end;

function TOneZTManage.CommitTranItem(QTranID: string; var QErrMsg: string): boolean;
var
  lZTItem: TOneZTItem;
begin
  Result := False;
  QErrMsg := '??????????????????';
  if self.FTranZTItemList.TryGetValue(QTranID, lZTItem) then
  begin
    try
      if lZTItem.ADTransaction.IsInTran then
      begin
        lZTItem.ADTransaction.TranCommit;
        lZTItem.FLastTime := Now;
        Result := True;
      end
      else
      begin
        Result := True;
      end;
    except
      on e: Exception do
      begin
        QErrMsg := '????????????,??????:' + e.Message;
      end;
    end;
  end
  else
  begin
    QErrMsg := '????????????????????????';
  end;
end;

function TOneZTManage.RollbackTranItem(QTranID: string; var QErrMsg: string): boolean;
var
  lZTItem: TOneZTItem;
begin
  Result := False;
  QErrMsg := '??????????????????';
  if self.FTranZTItemList.TryGetValue(QTranID, lZTItem) then
  begin
    try
      if 1 = 1 then
      begin
        lZTItem.ADTransaction.TranRollback;
        lZTItem.FLastTime := Now;
        Result := True;
      end
      else
      begin
        Result := True;
      end;
    except
      on e: Exception do
      begin
        QErrMsg := '????????????,??????:' + e.Message;
      end;
    end;
  end
  else
  begin
    QErrMsg := '????????????????????????';
  end;
end;

function TOneZTManage.StopZT(QZTCode: string; QStop: boolean; var QErrMsg: string): boolean;
var
  lZTPool: TOneZTPool;
begin
  Result := False;
  QErrMsg := '';
  QZTCode := QZTCode.ToUpper;
  if FZTPools.TryGetValue(QZTCode, lZTPool) then
  begin
    lZTPool.Stop := QStop;
    Result := True;
  end
  else
  begin
    QErrMsg := '?????????????????????';
  end;
end;

function TOneZTManage.InitZTPool(QZTSet: TOneZTSet; var QErrMsg: string): boolean;
var
  lZTPool: TOneZTPool;
  lZTCode: string;
begin
  Result := False;
  QErrMsg := '';
  if QZTSet.ZTCode.Trim = '' then
    exit;
  lZTCode := QZTSet.ZTCode.ToUpper;
  FLockObject.Enter;
  try
    if FZTPools.TryGetValue(lZTCode, lZTPool) then
    begin
      lZTPool.Free;
      FZTPools.Remove(lZTCode);
    end;
    lZTPool := TOneZTPool.Create(self, QZTSet);
    FZTPools.Add(lZTCode, lZTPool);
    Result := True;
  finally
    FLockObject.leave;
  end;
end;

function TOneZTManage.HaveZT(QZTCode: string): boolean;
begin
  QZTCode := QZTCode.ToUpper;
  Result := FZTPools.ContainsKey(QZTCode);
end;

function TOneZTManage.StarWork(QZTSetList: TList<TOneZTSet>; var QErrMsg: string): boolean;
var
  i: integer;
  lZTSet: TOneZTSet;
  lZTPool: TOneZTPool;
begin
  Result := False;
  QErrMsg := '';
  try
    // ??????????????????
    FLockObject.Enter;
    try
      for lZTPool in FZTPools.Values do
      begin
        // ?????????
        lZTPool.Stop := True;
        if lZTPool.FPoolWorkCount > 0 then
        begin
          QErrMsg := lZTPool.ZTCode + '???????????????????????????,??????????????????';
          exit;
        end;
      end;
      for lZTPool in FZTPools.Values do
      begin
        lZTPool.Free;
      end;
      FZTPools.Clear;
    finally
      FLockObject.leave;
    end;

    for i := 0 to QZTSetList.Count - 1 do
    begin
      lZTSet := QZTSetList[i];
      lZTSet.ZTCode := lZTSet.ZTCode.Trim;
      if not lZTSet.IsEnable then
        continue;
      if lZTSet.ZTCode = '' then
        continue;
      if lZTSet.ConnectionStr = '' then
        continue;
      if self.HaveZT(lZTSet.ZTCode) then
        continue;
      self.InitZTPool(lZTSet, QErrMsg);
      if lZTSet.IsMain then
      begin
        self.FZTMain := lZTSet.FZTCode.ToUpper;
      end;
    end;
    FTimerThread.StartWork;
    Result := True;
  except
    on e: Exception do
    begin
      QErrMsg := e.Message;
    end;
  end;
end;

function TOneZTManage.OpenData(QOpenData: TOneDataOpen; QOneDataResult: TOneDataResult): boolean;
var
  lOpenDatas: TList<TOneDataOpen>;
begin
  lOpenDatas := TList<TOneDataOpen>.Create;
  try
    lOpenDatas.Add(QOpenData);
    Result := self.OpenDatas(lOpenDatas, QOneDataResult)
  finally
    // ??????????????? QOneOpenData?????????
    lOpenDatas.Clear;
    lOpenDatas.Free;
  end;
end;

function TOneZTManage.OpenData(QOpenData: TOneDataOpen; QParams: array of variant; var QErrMsg: string): TFDMemtable;
var
  lZTItem: TOneZTItem;
  LZTQuery: TFDQuery;
  iParam: integer;
begin
  Result := nil;
  QErrMsg := '';
  lZTItem := self.LockZTItem(QOpenData.ZTCode, QErrMsg);
  if lZTItem = nil then
  begin
    if QErrMsg = '' then
      QErrMsg := '????????????' + QOpenData.ZTCode + '????????????,????????????';
    exit;
  end;

  try
    // ???????????????B??????,??????,?????????????????????????????????SQL??????????????????DML??????
    LZTQuery := lZTItem.GetQuery;
    if (QOpenData.PageSize > 0) and (QOpenData.PageIndex > 0) then
    begin
      LZTQuery.PacketRecords := QOpenData.PageSize;
    end
    else
    begin
      if QOpenData.PageSize > 0 then
        LZTQuery.PacketRecords := QOpenData.PageSize
      else
        LZTQuery.PacketRecords := -1;
    end;
    LZTQuery.SQL.Text := QOpenData.OpenSQL;
    // ????????????
    if LZTQuery.Params.Count <> length(QParams) then
    begin
      QErrMsg := 'SQL???????????????????????????????????????????????????';
      exit;
    end;
    for iParam := 0 to length(QParams) - 1 do
    begin
      LZTQuery.Params[iParam].Value := QParams[iParam];
    end;

    try
      LZTQuery.Open;
      if not LZTQuery.Active then
      begin
        QErrMsg := '??????????????????';
        exit;
      end;
      Result := TFDMemtable.Create(nil);
    except
      on e: Exception do
      begin
        QErrMsg := '????????????????????????,?????????' + e.Message;
        exit;
      end;
    end;
  finally
    lZTItem.UnLockWork;
  end;
end;

function TOneZTManage.OpenDatas(QOpenDatas: TList<TOneDataOpen>; var QOneDataResult: TOneDataResult): boolean;
var
  i, iParam, iErr: integer;
  lOpenData: TOneDataOpen;
  lZTItem: TOneZTItem;
  LZTQuery: TFDQuery;
  lMemoryStream, lParamStream: TMemoryStream;
  lRequestMilSec: integer;
  LJsonValue: TJSONData;
  lFileName, lFileGuid: string;
  lZip: TDeflater;

  lSQL: string;
  lErrMsg: string;
  lDataResultItem: TOneDataResultItem;
  lwatchTimer: TStopwatch;
  LFDParam: TParam;
  LOneParam: TOneParam;
  LSQLInfo: TSQLInfo;
  LPageField: TField;
  tempMsg: string;

  lFileStream: TFileStream;
begin
  Result := False;
  lErrMsg := '';
  if QOneDataResult = nil then
  begin
    QOneDataResult := TOneDataResult.Create;
  end;
  //???????????????
  if QOpenDatas.Count = 0 then
  begin
    QOneDataResult.ResultMsg := '????????????????????????';
    exit;
  end;
  lwatchTimer := TStopwatch.StartNew;
  try
    // ???????????????????????????
    for i := 0 to QOpenDatas.Count - 1 do
    begin
      lDataResultItem := TOneDataResultItem.Create;
      QOneDataResult.ResultCount := QOneDataResult.ResultCount + 1;
      QOneDataResult.ResultItems.Add(lDataResultItem);
      lOpenData := QOpenDatas[i];
      if lOpenData.ZTCode = '' then
        lOpenData.ZTCode := self.ZTMain;
      lOpenData.ZTCode := lOpenData.ZTCode.ToUpper;
      lZTItem := nil;
      // ?????????????????????,?????????????????????
      if lOpenData.TranID <> '' then
      begin
        lZTItem := self.GetTranItem(lOpenData.TranID, lErrMsg);
      end
      else
      begin
        lZTItem := self.LockZTItem(lOpenData.ZTCode, lErrMsg);
      end;
      if lZTItem = nil then
      begin
        if lErrMsg = '' then
          lErrMsg := '????????????' + lOpenData.ZTCode + '????????????,????????????';
        exit;
      end;

      try
        // lZTItem.ADQuery ?????????????????????Query?????????
        // lZTItem.FDConnection ????????????
        LZTQuery := lZTItem.ADQuery;
        InitSQLInfo(LSQLInfo);
        LSQLInfo.FDriver := lZTItem.FZTSet.FPhyDriver;
        LSQLInfo.FDriverVersion := lZTItem.FZTSet.FDBVersion;
        LSQLInfo.FPageIndex := lOpenData.PageIndex;
        LSQLInfo.FPageSize := lOpenData.PageSize;
        LSQLInfo.FSQL := lOpenData.OpenSQL;
        if not SetSQLInfo(LSQLInfo) then
        begin
          lErrMsg := LSQLInfo.FErrMsg;
          exit;
        end;
        LZTQuery.SQL.Text := LSQLInfo.FSQL;
        if LZTQuery.Params.Count <> 0 then
        begin
          if lOpenData.Params.Count <> LZTQuery.Params.Count then
          begin
            lErrMsg := '??????????????????';
            exit;
          end;
          // ????????????
          for iParam := 0 to LZTQuery.Params.Count - 1 do
          begin
            LFDParam := LZTQuery.Params[iParam];
            LOneParam := lOpenData.Params[iParam];
            // ????????????
            LFDParam.DataType :=
              TFieldType(GetEnumValue(TypeInfo(TFieldType), LOneParam.ParamDataType));
            LFDParam.ParamType :=
              TParamType(GetEnumValue(TypeInfo(TParamType), LOneParam.ParamType));
            // ?????????
            if LOneParam.ParamValue = const_OneParamIsNull_Value then
            begin
              // Null?????????
              LFDParam.Clear();
            end
            else
            begin
              case LFDParam.DataType of
                ftUnknown:
                begin
                  LFDParam.Value := LOneParam.ParamValue;
                end;
                ftBlob:
                begin
                  //lParamStream := TMemoryStream.Create;
                  //OneStreamString.StreamWriteBase64Str(
                  //  lParamStream, LOneParam.ParamValue);
                  //LFDParam.AsBlob := lParamStream.;
                end;
                else
                begin
                  LFDParam.Value := LOneParam.ParamValue;
                end;
              end;
            end;

          end;
        end;
        try
          LZTQuery.Open;
          if not LZTQuery.Active then
          begin
            lErrMsg := '??????????????????';
            exit;
          end;

          lDataResultItem.RecordCount := LZTQuery.RecordCount;
          lDataResultItem.ResultDataCount :=
            lDataResultItem.ResultDataCount + 1;
          //lOpenData.DataReturnMode := const_DataReturnMode_File;
          if lOpenData.DataReturnMode = const_DataReturnMode_File then
          begin
            lDataResultItem.ResultDataMode := const_DataReturnMode_File;
            lFileGuid := OneGUID.GetGUID32;
            lFileName := OneFileHelper.CombineExeRunPath('OnePlatform\OneDataTemp\' + lFileGuid + '.zip');

            lFileStream := TFileStream.Create(lFileName, fmCreate);
            lMemoryStream := TMemoryStream.Create;
            // ??????????????????
            lZip := nil;
            try
              LZTQuery.SaveToStream(lMemoryStream, TDataPacketFormat.dfBinary);
              lMemoryStream.Position := 0;

              lZip := TDeflater.Create(lMemoryStream, lFileStream, lMemoryStream.Size);
              lZip.Compress;
              lDataResultItem.ResultContext := lFileGuid;
            finally
              lFileStream.Free;
              lMemoryStream.Free;
              if lZip <> nil then
                lZip.Free;
            end;
          end
          else if lOpenData.DataReturnMode = const_DataReturnMode_Stream then
          begin
            lMemoryStream := TMemoryStream.Create;
            LZTQuery.SaveToStream(lMemoryStream, TDataPacketFormat.dfBinary);
            if lMemoryStream.Size >= 1024 * 1024 * 1 then
            begin
              lDataResultItem.ResultDataMode := const_DataReturnMode_File;
              lFileGuid := OneGUID.GetGUID32;
              lFileName := OneFileHelper.CombineExeRunPath('OnePlatform\OneDataTemp\' + lFileGuid + '.zip');
              // ??????????????????
              lFileStream := TFileStream.Create(lFileName, fmCreate);
              lZip := nil;
              try
                lMemoryStream.Position := 0;
                lZip := TDeflater.Create(lMemoryStream, lFileStream, lMemoryStream.Size);
                lZip.Compress;
                lDataResultItem.ResultContext := lFileGuid;
              finally
                lFileStream.Free;
                lMemoryStream.Free;
                if lZip <> nil then
                  lZip.Free;
              end;
            end
            else
            begin
              lDataResultItem.ResultDataMode := const_DataReturnMode_Stream;
              lDataResultItem.SetStream(lMemoryStream);
            end;
          end
          else if lOpenData.DataReturnMode = const_DataReturnMode_JSON then
          begin
            LJsonValue := OneDataJson.DataSetToJson(LZTQuery);
            try
              lDataResultItem.ResultContext := LJsonValue.AsJSON;
            finally
              LJsonValue.Free;
            end;
          end;
          // ????????????????????????????????????
          if ((lOpenData.PageSize > 0) and (lOpenData.PageIndex = 1)) or (lOpenData.PageRefresh) then
          begin
            lDataResultItem.ResultPage := True;
            LZTQuery := lZTItem.GetQuery;
            //LZTQuery.FetchOptions.RecsSkip := -1;
            //LZTQuery.FetchOptions.RecsMax := -1;
            lSQL := ClearOrderBySQL(lOpenData.OpenSQL);
            lSQL := 'select count(1) from ( ' + lSQL + ' ) tempCount';
            LZTQuery.SQL.Text := lSQL;
            for iParam := 0 to LZTQuery.Params.Count - 1 do
            begin
              LZTQuery.Params[iParam].Value :=
                lOpenData.Params[iParam].ParamValue;
            end;
            LZTQuery.Open();
            lSQL := LZTQuery.RecordCount.ToString;
            lSQL := LZTQuery.Fields.Count.ToString;
            lSQL := LZTQuery.Fields[0].AsString;
            lDataResultItem.ResultTotal := LZTQuery.Fields[0].AsInteger;
          end;
        except
          on e: Exception do
          begin
            lErrMsg := e.Message;
            exit;
          end;
        end;
      finally
        // ???????????????
        if lZTItem <> nil then
        begin
          lZTItem.UnLockWork();
        end;
      end;
      if lErrMsg <> '' then
      begin
        Result := False;
        exit;
        ;
      end;
    end;
    Result := True;
    QOneDataResult.ResultOK := True;
  finally
    QOneDataResult.ResultMsg := lErrMsg;
    lwatchTimer.Stop;
    lRequestMilSec := lwatchTimer.ElapsedMilliseconds;
    if (self.FLog <> nil) and (self.FLog.IsSQLLog) then
    begin
      self.FLog.WriteSQLLog('????????????[OpenDatas]:');
      self.FLog.WriteSQLLog('????????????:[' + lRequestMilSec.ToString + ']??????');
      self.FLog.WriteSQLLog('????????????:[' + lErrMsg + ']');
      for i := 0 to QOpenDatas.Count - 1 do
      begin
        lOpenData := QOpenDatas[i];
        self.FLog.WriteSQLLog('SQL??????:[' + lOpenData.OpenSQL + ']');
        for iParam := 0 to lOpenData.Params.Count - 1 do
        begin
          LOneParam := lOpenData.Params[iParam];
          self.FLog.WriteSQLLog('??????:[' + LOneParam.ParamName + ']???[' + LOneParam.ParamValue + ']');
        end;
      end;
    end;
  end;
end;

// ????????????
function TOneZTManage.SaveDatas(QSaveDMLDatas: TList<TOneDataSaveDML>; var QOneDataResult: TOneDataResult): boolean;
var
  lDataResultItem: TOneDataResultItem;

  lZTItemList: TDictionary<string, TOneZTItem>;
  lZTItem: TOneZTItem;
  LZTQuery: TFDQuery;
  i: integer;
  lDataSaveDML: TOneDataSaveDML;
  LOneParam: TOneParam;
  lErrMsg: string;
  lTranCount: integer;

  lSaveStream: TMemoryStream;
  lArrKeys: TArray<string>;
  iKey: integer;
  iUpdateErrCount, iParamCount, iParam: integer;
  lFieldType: TFieldType;
  isCommit: boolean;

  lRequestMilSec: integer;
  lwatchTimer: TStopwatch;

  tempFieldName: string;
  tempMsg: string;
begin
  Result := False;
  lErrMsg := '';
  isCommit := False;
  if QOneDataResult = nil then
  begin
    QOneDataResult := TOneDataResult.Create;
  end;
  // ??????
  lTranCount := 0;
  for i := 0 to QSaveDMLDatas.Count - 1 do
  begin
    lDataSaveDML := QSaveDMLDatas[i];
    if lDataSaveDML.ZTCode = '' then
      lDataSaveDML.ZTCode := self.ZTMain;
    lDataSaveDML.ZTCode := lDataSaveDML.ZTCode.ToUpper;
    if lDataSaveDML.DataSaveMode = const_DataSaveMode_SaveData then
    begin
      if lDataSaveDML.TableName = '' then
      begin
        QOneDataResult.ResultMsg :=
          '???' + (i + 1).ToString + '??????????????????????????????,???????????????????????????';
        exit;
      end;
      if lDataSaveDML.Primarykey = '' then
      begin
        QOneDataResult.ResultMsg :=
          '???' + (i + 1).ToString + '??????????????????????????????,???????????????????????????';
        exit;
      end;
      if lDataSaveDML.SaveData = '' then
      begin
        QOneDataResult.ResultMsg :=
          '???' + (i + 1).ToString + '?????????????????????????????????,?????????';
        exit;
      end;
    end
    else if lDataSaveDML.DataSaveMode = const_DataSaveMode_SaveDML then
    begin
      if lDataSaveDML.SQL = '' then
      begin
        QOneDataResult.ResultMsg :=
          '???' + (i + 1).ToString + '??????????????????DML???????????????,????????????????????????';
        exit;
      end;
    end
    else
    begin
      QOneDataResult.ResultMsg :=
        '???' + (i + 1).ToString + '?????????????????????????????????' + lDataSaveDML.DataSaveMode;
      exit;
    end;
    // ?????????????????????????????????,???????????????????????????,???????????????
    if lDataSaveDML.TranID <> '' then
    begin
      lTranCount := lTranCount + 1;
    end;
  end;
  if (lTranCount > 0) and (QSaveDMLDatas.Count <> lTranCount) then
  begin
    QOneDataResult.ResultMsg :=
      '??????????????????,??????????????????????????????????????????????????????' + lDataSaveDML.DataSaveMode;
    exit;
  end;

  // ?????????????????????????????????
  lwatchTimer := TStopwatch.StartNew;
  lZTItemList := TDictionary<string, TOneZTItem>.Create;
  try
    for i := 0 to QSaveDMLDatas.Count - 1 do
    begin
      lDataSaveDML := QSaveDMLDatas[i];
      if lDataSaveDML.TranID <> '' then
      begin
        if lZTItemList.TryGetValue(lDataSaveDML.TranID, lZTItem) then
        begin
          // ?????????????????????
          continue;
        end;
      end
      else
      begin
        // ???????????????????????????
        if lZTItemList.TryGetValue(lDataSaveDML.ZTCode, lZTItem) then
        begin
          continue;
        end;
      end;

      lZTItem := nil;
      if lDataSaveDML.TranID <> '' then
      begin
        lZTItem := self.GetTranItem(lDataSaveDML.TranID, lErrMsg);
      end
      else
      begin
        lZTItem := self.LockZTItem(lDataSaveDML.ZTCode, lErrMsg);
      end;
      if lZTItem = nil then
      begin
        // ????????????????????????
        QOneDataResult.ResultMsg := lErrMsg;
        exit;
      end;

      if lDataSaveDML.TranID <> '' then
      begin
        lZTItemList.Add(lDataSaveDML.TranID, lZTItem);
      end
      else
      begin
        lZTItemList.Add(lDataSaveDML.ZTCode, lZTItem);
      end;
    end;

    try
      try
        // ????????????
        for lZTItem in lZTItemList.Values do
        begin
          // ??????????????????,???????????????????????????
          if lZTItem.FCustTran then
            lZTItem.ADTransaction.TranStart;
        end;
        // ??????????????????????????????
        for i := 0 to QSaveDMLDatas.Count - 1 do
        begin
          lDataResultItem := TOneDataResultItem.Create;
          QOneDataResult.ResultItems.Add(lDataResultItem);
          lDataResultItem.ResultDataMode := const_DataReturnMode_Empty;
          lDataSaveDML := QSaveDMLDatas[i];
          lZTItem := nil;
          if lDataSaveDML.TranID <> '' then
          begin
            lZTItemList.TryGetValue(lDataSaveDML.TranID, lZTItem);
          end
          else
          begin
            lZTItemList.TryGetValue(lDataSaveDML.ZTCode, lZTItem);
          end;

          if lZTItem = nil then
          begin
            QOneDataResult.ResultMsg :=
              '????????????' + lDataSaveDML.ZTCode + '????????????';
            exit;
          end;

          if lDataSaveDML.DataSaveMode = const_DataSaveMode_SaveData then
          begin
            // ????????????
            LZTQuery := lZTItem.ADQuery;
            LZTQuery.SQL.Text := 'select *  from ' + lDataSaveDML.TableName;
            LZTQuery.TableName := lDataSaveDML.TableName;
            LZTQuery.KeyFields := lDataSaveDML.Primarykey;
            LZTQuery.UpdateMode := TUpdateMode.upWhereKeyOnly;
            if lDataSaveDML.UpdateMode <> '' then
            begin
              LZTQuery.UpdateMode :=
                TUpdateMode(GetEnumValue(TypeInfo(TUpdateMode), lDataSaveDML.UpdateMode));
            end;
            // ????????????????????????????????????
            lSaveStream := lZTItem.DataStream;
            OneStreamString.StreamWriteBase64Str(lSaveStream,
              lDataSaveDML.SaveData);
            lSaveStream.Position := 0;
            // ?????????
            LZTQuery.LoadFromStream(lSaveStream, TDataPacketFormat.dfBinary);
            if not LZTQuery.Active then
            begin
              QOneDataResult.ResultMsg := '?????????' + (i + 1).ToString + '????????????';
              exit;
            end;
            tempMsg := LZTQuery.RecordCount.ToString;
            // ????????????????????????
            if lDataSaveDML.Primarykey <> '' then
            begin
              lArrKeys := lDataSaveDML.Primarykey.Split([';', ','], TStringSplitOptions.ExcludeEmpty);
              for iKey := Low(lArrKeys) to High(lArrKeys) do
              begin
                // ??????????????????
                LZTQuery.FieldByName(lArrKeys[iKey]).ProviderFlags :=
                  [pfInUpdate, pfInWhere, pfInKey];
              end;
            end;
            if lDataSaveDML.NotUpdateFields <> nil then
            begin
              for iKey := 0 to lDataSaveDML.NotUpdateFields.Count - 1 do
              begin
                tempFieldName := lDataSaveDML.NotUpdateFields[iKey];
                //???????????????????????????
                LZTQuery.FieldByName(tempFieldName).ProviderFlags :=
                  LZTQuery.FieldByName(tempFieldName).ProviderFlags - [pfInUpdate];
              end;
            end;
            // ???????????????????????????
            if lDataSaveDML.OtherKeys <> '' then
            begin
              lArrKeys := lDataSaveDML.OtherKeys.Split([';', ','], TStringSplitOptions.ExcludeEmpty);
              for iKey := Low(lArrKeys) to High(lArrKeys) do
              begin
                // ??????????????????
                LZTQuery.FieldByName(lArrKeys[iKey]).ProviderFlags :=
                  [pfInUpdate, pfInWhere, pfInKey];
              end;
            end;

            try
              LZTQuery.ApplyUpdates(0);
              lDataResultItem.RecordCount := LZTQuery.RowsAffected;
              if lDataSaveDML.IsReturnData then
              begin
                // ???????????????,???????????????ID?????????????????????
                lDataResultItem.ResultDataMode := const_DataReturnMode_Stream;
                lSaveStream := TMemoryStream.Create;
                LZTQuery.SaveToStream(lSaveStream, TDataPacketFormat.dfBinary);
                lSaveStream.Position := 0;
                lDataResultItem.SetStream(lSaveStream);
              end;
            except
              on e: Exception do
              begin
                QOneDataResult.ResultMsg :=
                  '??????????????????:????????????:' + e.Message;
                exit;
              end;
            end;
            if iUpdateErrCount > 0 then
            begin
              if lZTItem.FException.FErrmsg <> '' then
                QOneDataResult.ResultMsg :=
                  '??????????????????:????????????:' + lZTItem.FException.FErrmsg;
              exit;
            end;
          end
          else if lDataSaveDML.DataSaveMode = const_DataSaveMode_SaveDML then
          begin
            // ??????DML??????
            LZTQuery := lZTItem.ADQuery;
            LZTQuery.SQL.Text := lDataSaveDML.SQL;
            iParamCount := LZTQuery.Params.Count;
            if iParamCount > 0 then
            begin
              if iParamCount > lDataSaveDML.Params.Count then
              begin
                QOneDataResult.ResultMsg :=
                  '?????????' + (i + 1).ToString + '??????????????????';
                exit;
              end;

              for iParam := 0 to LZTQuery.Params.Count - 1 do
              begin
                LOneParam := lDataSaveDML.Params[iParam];
                lFieldType := TFieldType.ftUnknown;
                if LOneParam.ParamDataType <> '' then
                begin
                  lFieldType :=
                    TFieldType(GetEnumValue(TypeInfo(TFieldType), LOneParam.ParamDataType));
                end;
                LZTQuery.Params[iParam].DataType := lFieldType;

                if LOneParam.ParamValue = const_OneParamIsNull_Value then
                begin
                  LZTQuery.Params[iParam].Clear();
                end
                else if lFieldType = TFieldType.ftBlob then
                begin
                  //LZTQuery.Params[iParam].AsStream :=
                  //  OneStreamString.Base64ToStream(LOneParam.ParamValue);
                end
                else
                  LZTQuery.Params[iParam].Value := LOneParam.ParamValue;
              end;
            end;
            try
              LZTQuery.ExecSQL;
              lDataResultItem.RecordCount := LZTQuery.RowsAffected;
            except
              on e: Exception do
              begin
                QOneDataResult.ResultMsg := '??????DML????????????,??????:' + e.Message;
                exit;
              end;
            end;
            if lDataSaveDML.AffectedMustCount > 0 then
            begin
              if LZTQuery.RowsAffected <> lDataSaveDML.AffectedMustCount then
              begin
                QOneDataResult.ResultMsg :=
                  '??????DML????????????,??????:??????????????????[' + lDataSaveDML.AffectedMustCount.ToString + '],??????????????????[' + LZTQuery.RowsAffected.ToString + ']';
                exit;
              end;
            end;
            if lDataSaveDML.AffectedMaxCount > 0 then
            begin
              if LZTQuery.RowsAffected > lDataSaveDML.AffectedMaxCount then
              begin
                QOneDataResult.ResultMsg :=
                  '??????DML????????????,??????:??????????????????[' + lDataSaveDML.AffectedMaxCount.ToString + '],??????????????????[' + LZTQuery.RowsAffected.ToString + ']';
                exit;
              end;
            end;
          end;
        end;
        for lZTItem in lZTItemList.Values do
        begin
          if not lZTItem.FCustTran then
            lZTItem.ADTransaction.TranCommit;
        end;
        QOneDataResult.ResultOK := True;
        isCommit := True;
      except
        on e: Exception do
        begin
          QOneDataResult.ResultOK := False;
          isCommit := False;
          QOneDataResult.ResultMsg := '??????????????????:????????????:' + e.Message;
          exit;
        end;
      end;
    finally
      // ????????????
      if not isCommit then
      begin
        for lZTItem in lZTItemList.Values do
        begin
          if not lZTItem.FCustTran then
            lZTItem.ADTransaction.TranRollback;
        end;
      end;
    end;
  finally
    lwatchTimer.Stop;
    lRequestMilSec := lwatchTimer.ElapsedMilliseconds;
    for lZTItem in lZTItemList.Values do
    begin
      // ????????????
      if not lZTItem.FCustTran then
        lZTItem.UnLockWork;
    end;
    lZTItemList.Clear;
    lZTItemList.Free;

    if (self.FLog <> nil) and (self.FLog.IsSQLLog) then
    begin
      self.FLog.WriteSQLLog('????????????[SaveDatas]:');
      self.FLog.WriteSQLLog('????????????:[' + lRequestMilSec.ToString + ']??????');
      self.FLog.WriteSQLLog('????????????:[' + QOneDataResult.ResultMsg + ']');
      for i := 0 to QSaveDMLDatas.Count - 1 do
      begin
        lDataSaveDML := QSaveDMLDatas[i];
        self.FLog.WriteSQLLog('SQL??????:[' + lDataSaveDML.SQL + ']');
        for iParam := 0 to lDataSaveDML.Params.Count - 1 do
        begin
          LOneParam := lDataSaveDML.Params[iParam];
          self.FLog.WriteSQLLog('??????:[' + LOneParam.ParamName + ']???[' + LOneParam.ParamValue + ']');
        end;
      end;
    end;
  end;
end;

function TOneZTManage.ExecSQL(QDataSaveDML: TOneDataSaveDML; QParams: array of variant; var QErrMsg: string): integer;
var
  lZTItem: TOneZTItem;
  LZTQuery: TFDQuery;
  iParam: integer;
  isCommit: boolean;
begin
  Result := -1;
  QErrMsg := '';
  lZTItem := self.LockZTItem(QDataSaveDML.ZTCode, QErrMsg);
  if lZTItem = nil then
  begin
    if QErrMsg = '' then
      QErrMsg := '????????????' + QDataSaveDML.ZTCode + '????????????,????????????';
    exit;
  end;

  isCommit := False;
  lZTItem.ADTransaction.TranStart;
  try
    // ???????????????B??????,??????,?????????????????????????????????SQL??????????????????DML??????
    LZTQuery := lZTItem.GetQuery;
    LZTQuery.SQL.Text := QDataSaveDML.SQL;
    // ????????????
    if LZTQuery.Params.Count <> length(QParams) then
    begin
      QErrMsg := 'SQL???????????????????????????????????????????????????';
      exit;
    end;
    for iParam := 0 to length(QParams) - 1 do
    begin
      LZTQuery.Params[iParam].Value := QParams[iParam];
    end;

    try
      LZTQuery.ExecSQL;
      Result := LZTQuery.RowsAffected;
      if QDataSaveDML.AffectedMustCount > 0 then
      begin
        if LZTQuery.RowsAffected <> QDataSaveDML.AffectedMustCount then
        begin
          QErrMsg := '??????DML????????????,??????:??????????????????[' + QDataSaveDML.AffectedMustCount.ToString + '],??????????????????[' + LZTQuery.RowsAffected.ToString + ']';
          exit;
        end;
      end;
      if QDataSaveDML.AffectedMaxCount > 0 then
      begin
        if LZTQuery.RowsAffected > QDataSaveDML.AffectedMaxCount then
        begin
          QErrMsg := '??????DML????????????,??????:??????????????????[' + QDataSaveDML.AffectedMaxCount.ToString + '],??????????????????[' + LZTQuery.RowsAffected.ToString + ']';
          exit;
        end;
      end;
      lZTItem.ADTransaction.TranCommit;
      isCommit := True;
      QErrMsg := 'true';
    except
      on e: Exception do
      begin
        QErrMsg := '????????????????????????,?????????' + e.Message;
        exit;
      end;
    end;
  finally
    if not isCommit then
    begin
      lZTItem.ADTransaction.TranRollback;
    end;
    lZTItem.UnLockWork;
  end;
end;

procedure TOneZTManage.BuildStoredSQL(QPhyDirver: string; QOpenData: TOneDataOpen);
var
  lOneParam: TOneParam;
  lParamName: string;
  iParam, iParamCount: integer;
  lParamType: TParamType;
  lFieldType: TFieldType;
  lSizeStr: string;
  LSQL: string;
  lDeclareSQL: string;
  lDeclareSQLParams: string;
  lSetSQL: string;
  lMakeExecSQL: string;
  lMakeExecSQLParams: string;
  lExecuteSQL: string;
  lExecuteSQLDeclare: string;
  lExecuteSQLParams: string;
  lSelectParamsResult: string;
begin
  //??????
  lDeclareSQL := '';
  lSetSQL := '';
  lMakeExecSQL := '';
  lMakeExecSQLParams := '';
  lExecuteSQL := '';
  lExecuteSQLDeclare := '';
  lExecuteSQLParams := '';
  lSelectParamsResult := '';
  LSQL := '';
  if QPhyDirver.StartsWith(Driver_MSSQLServer) then
  begin
    {??????SQLDB?????????????????????????????????????????????,???????????????SQL?????????????????????????????????????????????
    declare @code nvarchar(30),@name nvarchar(30), @Sqls nvarchar(max)
    set @code='11'
    set @name='flm'
    set @Sqls='exec SP_TEST @name,@code output'
    exec sp_executesql @sqls,N'@name nvarchar(30),@code nvarchar(30) output',@name,@code output
    select @code }
    if QOpenData.Params = nil then
    begin
      QOpenData.Params := TList<TOneParam>.Create;
    end;
    //???????????????SQL??????
    lDeclareSQL := ' declare @OneZSysMakeSQL nvarchar(max) ';
    lMakeExecSQL := 'set @OneZSysMakeSQL='; //set @OneZSysMakeSQL=lMakeExecSQL ???????????????
    lMakeExecSQLParams := ' exec ' + QOpenData.SPName + ' ';
    lExecuteSQL := 'exec sp_executesql @OneZSysMakeSQL ';

    iParamCount := QOpenData.Params.Count;
    for iParam := 0 to iParamCount - 1 do
    begin
      lOneParam := QOpenData.Params[iParam];
      lParamName := lOneParam.ParamName;
      if lParamName.StartsWith('@') then
      begin
        lParamName := lParamName.Substring(1);
      end;
      lParamType := TParamType(GetEnumValue(TypeInfo(TParamType), lOneParam.ParamType));
      lFieldType := TFieldType(GetEnumValue(TypeInfo(TFieldType), lOneParam.ParamDataType));
      if lOneParam.ParamSize > 0 then
        lSizeStr := lOneParam.ParamSize.ToString
      else
        lSizeStr := '255';
      //??????Set??????
      lSetSQL := lSetSQL + ' set @' + lParamName + '=:' + lParamName + ' ' + #13#10;
      //?????? MakeExecSQL??????
      if lParamType in [ptInputOutput, ptOutput] then
      begin
        lMakeExecSQLParams := lMakeExecSQLParams + ' @' + lParamName + ' output ';
        lExecuteSQLParams := lExecuteSQLParams + ' @' + lParamName + ' output ';
      end
      else
      begin
        lMakeExecSQLParams := lMakeExecSQLParams + ' @' + lParamName + ' ';
        lExecuteSQLParams := lExecuteSQLParams + ' @' + lParamName + ' ';
      end;
      if iParam < iParamCount - 1 then
      begin
        lMakeExecSQLParams := lMakeExecSQLParams + ',';
        lExecuteSQLParams := lExecuteSQLParams + ',';
      end;
      //??????Declare??????
      case lFieldType of
        ftString, ftWideString, ftFixedChar, ftFixedWideChar:
        begin
          lDeclareSQLParams := lDeclareSQLParams + '@' + lParamName + ' nvarchar(' + lSizeStr + ')';
          lExecuteSQLDeclare := lDeclareSQLParams;
        end;
        ftSmallint, ftInteger:
        begin
          lDeclareSQLParams := lDeclareSQLParams + '@' + lParamName + ' int ';
          lExecuteSQLDeclare := lDeclareSQLParams;
        end;
        ftLargeint:
        begin
          lDeclareSQLParams := lDeclareSQLParams + '@' + lParamName + ' bigint ';
          lExecuteSQLDeclare := lDeclareSQLParams;
        end;
        ftWord, ftFloat, ftCurrency, ftBCD, ftFMTBcd:
        begin
          lDeclareSQLParams := lDeclareSQLParams + '@' + lParamName + ' float ';
          lExecuteSQLDeclare := lDeclareSQLParams;
        end;
        ftVariant:
        begin
          lSizeStr := '255';
          lDeclareSQLParams := lDeclareSQLParams + ',@' + lParamName + ' nvarchar(' + lSizeStr + ')';
          lExecuteSQLDeclare := lDeclareSQLParams;
        end
        else
        begin
          lSizeStr := '255';
          lDeclareSQLParams := lDeclareSQLParams + ',@' + lParamName + ' nvarchar(' + lSizeStr + ')';
          lExecuteSQLDeclare := lDeclareSQLParams;
        end;
      end;
      //????????????
      lSelectParamsResult := lSelectParamsResult + ' @' + lParamName + ' as ' + lParamName;
      //??????Output
      if lParamType in [ptInputOutput, ptOutput] then
      begin
        lExecuteSQLDeclare := lExecuteSQLDeclare + ' output';
      end;
      //?????? lExecuteSQLDeclare
      if iParam < iParamCount - 1 then
      begin
        lDeclareSQLParams := lDeclareSQLParams + ' , ';
        lExecuteSQLDeclare := lExecuteSQLDeclare + ' , ';
        lSelectParamsResult := lSelectParamsResult + ' , ';
      end;
    end;
    //??????SQL
    if lDeclareSQLParams <> '' then
    begin
      lDeclareSQL := lDeclareSQL + ',' + lDeclareSQLParams;
    end;
    lMakeExecSQL := lMakeExecSQL + QuoTedStr(lMakeExecSQLParams);
    if lExecuteSQLDeclare <> '' then
    begin
      lExecuteSQL := lExecuteSQL + ',N' + QuoTedStr(lExecuteSQLDeclare);
    end;
    if lExecuteSQLParams <> '' then
    begin
      lExecuteSQL := lExecuteSQL + ',' + lExecuteSQLParams;
    end;
    if lSelectParamsResult <> '' then
    begin
      lSelectParamsResult := ' select ' + lSelectParamsResult;
    end;
    //??????SQL
    LSQL := lDeclareSQL + #13#10 + lSetSQL + #13#10 + lMakeExecSQL + #13#10 + lExecuteSQL + #13#10 + lSelectParamsResult;
  end;
  if LSQL <> '' then
  begin
    QOpenData.OpenSQL := LSQL;
  end;
end;

function TOneZTManage.ExecStored(QOpenData: TOneDataOpen; var QOneDataResult: TOneDataResult): boolean;
var
  lZTItem: TOneZTItem;
  lErrMsg: string;
  lFDStored: TFDStoredProc;
  i, iParam: integer;
  tempStr: string;
  LFDParam: TParam;
  lDictParam: TDictionary<string, TOneParam>;
  LOneParam: TOneParam;
  lStream, lParamStream: TMemoryStream;
  lDataResultItem: TOneDataResultItem;
  lPTResult: integer;
  lRequestMilSec: integer;
  lwatchTimer: TStopwatch;
  isOutParam: boolean;
  lField: TField;
  lFielName: string;
begin
  Result := False;
  lPTResult := 0;
  if QOneDataResult = nil then
  begin
    QOneDataResult := TOneDataResult.Create;
  end;
  if QOpenData.Params = nil then
  begin
    QOpenData.Params := TList<TOneParam>.Create;
  end;
  // ????????????
  if QOpenData = nil then
  begin
    QOneDataResult.ResultMsg := '???????????????????????????????????????';
    exit;
  end;
  if QOpenData.OpenSQL.Trim = '' then
  begin
    QOneDataResult.ResultMsg := '?????????????????????SQL????????????';
    exit;
  end;

  lZTItem := nil;
  lErrMsg := '';
  lwatchTimer := TStopwatch.StartNew;
  lDictParam := TDictionary<string, TOneParam>.Create;
  try
    for iParam := 0 to QOpenData.Params.Count - 1 do
    begin
      LOneParam := QOpenData.Params[iParam];
      lDictParam.Add(LOneParam.ParamName.ToLower, LOneParam);
    end;

    if QOpenData.ZTCode = '' then
      QOpenData.ZTCode := self.ZTMain;
    QOpenData.ZTCode := QOpenData.ZTCode.ToUpper;
    lZTItem := nil;
    // ?????????????????????,?????????????????????
    if QOpenData.TranID <> '' then
    begin
      lZTItem := self.GetTranItem(QOpenData.TranID, lErrMsg);
    end
    else
    begin
      lZTItem := self.LockZTItem(QOpenData.ZTCode, lErrMsg);
    end;
    if lZTItem = nil then
    begin
      if lErrMsg = '' then
        lErrMsg := '????????????' + QOpenData.ZTCode + '????????????,????????????';
      exit;
    end;
    self.BuildStoredSQL(lZTItem.FZTSet.PhyDriver, QOpenData);
    lFDStored := lZTItem.ADStoredProc;
    lFDStored.SQL.Text := QOpenData.OpenSQL;
    lFDStored.PackageName := QOpenData.PackageName;
    lFDStored.StoredProcName := QOpenData.SPName;
    // ????????????
    lFDStored.Prepare;
    if not lFDStored.Prepared then
    begin
      lErrMsg := '????????????????????????,?????????????????????????????????[' + QOpenData.SPName + ']';
      exit;
    end;
    for iParam := lFDStored.Params.Count - 1 downto 0 do
    begin
      LFDParam := lFDStored.Params[iParam];
      if LFDParam.ParamType = TParamType.ptResult then
      begin
        lPTResult := lPTResult + 1;
        continue;
      end;
      if LFDParam.Name.StartsWith('@') then
      begin
        // SQL????????????????????????@??????
        LFDParam.Name := LFDParam.Name.Substring(1);
      end;
    end;

    if QOpenData.Params.Count <> lFDStored.Params.Count - lPTResult then
    begin
      tempStr := '??????????????????->?????????????????????[' + lFDStored.Params.Count.ToString + '],??????[';
      for iParam := lFDStored.Params.Count - 1 downto 0 do
      begin
        tempStr := tempStr + lFDStored.Params[iParam].Name;
      end;
      tempStr := tempStr + ';?????????????????????[' + QOpenData.Params.Count.ToString + '],??????[';
      for iParam := QOpenData.Params.Count - 1 downto 0 do
      begin
        tempStr := tempStr + QOpenData.Params[iParam].ParamName;
      end;
      tempStr := tempStr + ']';
      lErrMsg := tempStr;
      exit;
    end;
    // ????????????
    for iParam := 0 to lFDStored.Params.Count - 1 do
    begin
      LFDParam := lFDStored.Params[iParam];
      if LFDParam.ParamType = TParamType.ptResult then
      begin
        continue;
      end;
      // ????????????
      LOneParam := nil;
      if not lDictParam.TryGetValue(LFDParam.Name.ToLower, LOneParam) then
      begin
        lErrMsg := '??????[' + LFDParam.Name + '],????????????????????????,???????????????????????????';
        exit;
      end;
      if LFDParam.ParamType in [TParamType.ptInputOutput, TParamType.ptOutput] then
        isOutParam := True;
      if LFDParam.ParamType in [TParamType.ptInput, TParamType.ptInputOutput, TParamType.ptOutput] then
      begin
        if LFDParam.DataType = ftWideMemo then
        begin
          LFDParam.AsMemo := LOneParam.ParamValue;
        end
        else if LFDParam.DataType = ftWideString then
        begin
          LFDParam.AsWideString := LOneParam.ParamValue;
        end
        else if LFDParam.DataType in ftBlobTypes then
        begin
          //lParamStream := TMemoryStream.Create;
          //OneStreamString.StreamWriteBase64Str(lParamStream,
          //  LOneParam.ParamValue);
          //LFDParam.AsStream := lParamStream;
        end
        else
          LFDParam.Value := LOneParam.ParamValue;
      end;
    end;
    // ExecProc ????????????????????????????????????
    try
      if (QOpenData.SPIsOutData) or (isOutParam) then
      begin
        lFDStored.Open;
      end
      else
      begin
        lFDStored.ExecSQL;
      end;
      //tempStr := lFDStored.Fields[0].FieldName;
      // ????????????????????????,???????????????,???????????????????????????
      if (not isOutParam) and (not QOpenData.SPIsOutData) then
      begin
        lDataResultItem := TOneDataResultItem.Create;
        QOneDataResult.ResultItems.Add(lDataResultItem);
      end;
      begin
        //????????????
        if not lFDStored.Active then
        begin
          lErrMsg := '???????????????????????????????????????????????????,?????????;';
          exit;
        end;
        if isOutParam and (not QOpenData.SPIsOutData) then
        begin
          lDataResultItem := TOneDataResultItem.Create;
          QOneDataResult.ResultItems.Add(lDataResultItem);
          for iParam := 0 to lFDStored.Fields.Count - 1 do
          begin
            lField := lFDStored.Fields[iParam];
            lFielName := lFDStored.Fields[iParam].FieldName;
            if lDictParam.TryGetValue(lFielName.ToLower, LOneParam) then
            begin
              LOneParam := TOneParam.Create;
              lDataResultItem.ResultParams.Add(LOneParam);
              LOneParam.ParamName := lFielName;
              LOneParam.ParamValue := VarToStr(lField.Value);
            end;
          end;
        end
        else
        begin
          lDataResultItem := TOneDataResultItem.Create;
          QOneDataResult.ResultItems.Add(lDataResultItem);
          lDataResultItem.ResultDataMode := const_DataReturnMode_Stream;
          lStream := TMemoryStream.Create;
          lFDStored.SaveToStream(lStream, TDataPacketFormat.dfBinary);
          lDataResultItem.SetStream(lStream);
          lDataResultItem := QOneDataResult.ResultItems[0];
        end;
      end;
      Result := True;
      QOneDataResult.ResultOK := True;
    except
      on e: Exception do
      begin
        lErrMsg := '????????????????????????:' + e.Message;
        exit;
      end;
    end;
  finally
    QOneDataResult.ResultMsg := lErrMsg;
    if lZTItem <> nil then
    begin
      lZTItem.UnLockWork;
    end;
    lDictParam.Clear;
    lDictParam.Free;
    lwatchTimer.Stop;
    lRequestMilSec := lwatchTimer.ElapsedMilliseconds;
    if (self.FLog <> nil) and (self.FLog.IsSQLLog) then
    begin
      self.FLog.WriteSQLLog('????????????[ExecStored]:');
      self.FLog.WriteSQLLog('????????????:[' + lRequestMilSec.ToString + ']??????');
      self.FLog.WriteSQLLog('????????????:[' + lErrMsg + ']');
      self.FLog.WriteSQLLog('SQL??????:[' + QOpenData.SPName + ']');
      for iParam := 0 to QOpenData.Params.Count - 1 do
      begin
        LOneParam := QOpenData.Params[iParam];
        self.FLog.WriteSQLLog('??????:[' + LOneParam.ParamName + ']???[' + LOneParam.ParamValue + ']');
      end;
    end;
  end;

end;

procedure TOneZTManage.InitPhyDriver(QDriverName: string);
var
  lFileName: string;
  lLib: TSQLDBLibraryLoader;
begin
  if QDriverName = '' then
    exit;
  if self.FLibrarys.ContainsKey(QDriverName) then
  begin
    exit;
  end;
  if QDriverName.StartsWith(Driver_MSSQLServer) then
    exit;
  {$ifdef CPUX86}
  lFileName := 'OnePlatform\OnePhyDBDLL\'+QDriverName+'\32\'
   {$else CPUX64}
  lFileName := 'OnePlatform\OnePhyDBDLL\' + QDriverName + '\64\';
  {$endif}
  //?????????????????????
  lFileName := OneFileHelper.CombineExeRunPath(lFileName);
  if not DirectoryExists(lFileName) then
    ForceDirectories(lFileName);
  //??????????????????
  lLib := TSQLDBLibraryLoader.Create(nil);
  self.FLibrarys.add(QDriverName, lLib);
  lLib.ConnectionType := QDriverName;
  //if QDriverName.StartsWith(Driver_MSSQLServer) then
  //begin
  //  lLib.ConnectionType := Driver_MSSQLServer;
  //  lFileName := OneFileHelper.CombinePath(lFileName, 'dblib.dll');
  //end
  //else
  if QDriverName.StartsWith(Driver_MySQL) then
  begin
    lLib.ConnectionType := QDriverName;
    lFileName := OneFileHelper.CombinePath(lFileName, 'libmysql.dll');
  end
  else
  if QDriverName.StartsWith(Driver_Oracle) then
  begin
    lLib.ConnectionType := Driver_Oracle;
    lFileName := OneFileHelper.CombinePath(lFileName, 'oci.dll');
  end
  else
  if QDriverName.StartsWith(Driver_PostgreSQL) then
  begin
    lLib.ConnectionType := Driver_PostgreSQL;
    lFileName := OneFileHelper.CombinePath(lFileName, 'libpq.dll');
  end
  else
  if QDriverName.StartsWith(Driver_SQLite3) then
  begin
    lLib.ConnectionType := Driver_SQLite3;
    lFileName := OneFileHelper.CombinePath(lFileName, 'sqlite3.dll');
  end
  else
  if QDriverName.StartsWith(Driver_Sybase) then
  begin
    lLib.ConnectionType := Driver_Sybase;
    lFileName := OneFileHelper.CombinePath(lFileName, 'dblib.dll');
  end
  else
  if QDriverName.StartsWith(Driver_Firebird) then
  begin
    lLib.ConnectionType := Driver_Firebird;
    lFileName := OneFileHelper.CombinePath(lFileName, 'fbclient.dll');
  end;
  if fileExists(lFileName) then
  begin
    lLib.LibraryName := lFileName;
    lLib.Enabled := True;
    lLib.LoadLibrary;
  end;
end;

procedure UnInitPhyDriver;
begin
end;

procedure InitSQLInfo(var QSQLInfo: TSQLInfo);
begin
  QSQLInfo.FDriver := '';
  QSQLInfo.FDriverVersion := '';
  QSQLInfo.FPageIndex := -1;
  QSQLInfo.FPageSize := -1;
  QSQLInfo.FSQL := '';
  QSQLInfo.FOrderByLine := -1;
  QSQLInfo.FOrderSQL := '';
  QSQLInfo.FPageField := '';
  QSQLInfo.FErrMsg := '';
end;

function ClearOrderBySQL(QSQL: string): string;
var
  i: integer;
  lTempStr: string;
  lOrderIndex, lByIndex: integer;
begin
  lTempStr := '';
  lOrderIndex := -1;
  lByIndex := -1;
  for i := Low(QSQL) to High(QSQL) do
  begin
    if (QSQL[i] <> ' ') and (QSQL[i] <> char(13)) and (QSQL[i] <> char(10)) then
    begin
      lTempStr := lTempStr + QSQL[i];
    end
    else
    begin
      lTempStr := lTempStr.ToLower;
      if (lOrderIndex = -1) and (lTempStr = 'order') then
      begin
        lOrderIndex := i - 5;
      end
      else
      begin
        if (lOrderIndex > 0) then
        begin
          if lTempStr = 'by' then
          begin
            lByIndex := i - 2;
          end
          else if lTempStr = 'from' then
          begin
            if i > lOrderIndex then
            begin
              lOrderIndex := -1;
              lByIndex := -1;
            end;
          end
          else if (lByIndex = -1) and (length(lTempStr) > 0) then
          begin
            lOrderIndex := -1;
          end;
        end;
      end;
      lTempStr := '';
    end;
  end;
  if lOrderIndex > 0 then
  begin
    Result := Copy(QSQL, Low(''), lOrderIndex - 1);
  end
  else
  begin
    Result := QSQL;
  end;
end;

function SetSQLInfo(var QSQLInfo: TSQLInfo): boolean;
var
  lList: TStringList;
  i, iDriverVersion, tempIStar, tempIEnd: integer;
  tempSQL: string;
  tempOrderBySQL: string;
  lRegExpr: TRegExpr;
begin
  Result := False;
  if QSQLInfo.FPageSize <= 0 then
  begin
    //????????????????????????
    Result := True;
    exit;
  end;
  if QSQLInfo.FDriver = '' then
  begin
    QSQLInfo.FErrMsg := '?????????????????????,??????????????????SQL';
    exit;
  end;
  if QSQLInfo.FPageIndex <= 0 then
    QSQLInfo.FPageIndex := 1;   //?????????
  lList := TStringList.Create;
  try
    lList.Text := QSQLInfo.FSQL;
    for i := 0 to lList.Count - 1 do
    begin
      tempSQL := lList[i];
      tempSQL := tempSQL.Trim();
      if tempSQL.StartsWith('order ', True) then
      begin
        tempSQL := tempSQL.Substring(5);
        tempSQL := tempSQL.Trim;
        if tempSQL.StartsWith('by ', True) then
        begin
          QSQLInfo.FOrderByLine := i;
          QSQLInfo.FOrderSQL := lList[i];
        end;
      end;
    end;

    //??????
    iDriverVersion := 0;
    tryStrToInt(QSQLInfo.FDriverVersion, iDriverVersion);
    if QSQLInfo.FDriver.StartsWith(Driver_MSSQLServer) then
    begin
      //SQLServer???????????????
      //?????? offset 0  rows fetch next 1  rows only
      if iDriverVersion >= 2012 then
      begin
        if QSQLInfo.FOrderByLine > 0 then
        begin
          tempSQL := ' offset ' + (QSQLInfo.FPageIndex - 1).Tostring() + '  rows fetch next ' + QSQLInfo.FPageSize.ToString + '  rows only';
          lList.Add(tempSQL);
          QSQLInfo.FSQL := lList.Text;
        end
        else
        begin
          //???????????????order by ???????????????,offset????????????order by ??????
          lList.Add(' order by 1 ');
          tempSQL := ' offset ' + (QSQLInfo.FPageIndex - 1).Tostring() + '  rows fetch next ' + QSQLInfo.FPageSize.ToString + '  rows only';
          lList.Add(tempSQL);
          QSQLInfo.FSQL := lList.Text;
        end;
      end
      else
      begin
        //??????2012??????rowNumber????????????,?????????Order by???????????????
        tempOrderBySQL := '';
        if QSQLInfo.FOrderByLine <= 0 then
        begin
          QSQLInfo.FErrMsg :=
            'MSSQL??????2012???????????????,???????????????order by ???????????? ??????????????????,???order by????????????????????????SQL';
          exit;
        end;
        if QSQLInfo.FOrderByLine > 0 then
        begin
          tempOrderBySQL := lList[QSQLInfo.FOrderByLine];
          lList[QSQLInfo.FOrderByLine] := '';
          //orderbySQL???????????? ???.??????????????????????????? SysOneT.??????over number????????????SQL?????????
          lRegExpr := TRegExpr.Create;
          try
            lRegExpr.Expression := '([a-zA-Z]{0,}\.)';
            tempOrderBySQL := lRegExpr.Replace(tempOrderBySQL, 'SysOneT.');
          finally
            lRegExpr.Free;
          end;
        end;
        tempSQL := lList.Text;
        tempIStar := (QSQLInfo.FPageIndex - 1) * QSQLInfo.FPageSize;
        tempIEnd := tempIStar + QSQLInfo.FPageSize;
        tempSQL := ' SELECT SysOneT.* FROM ' + ' ( SELECT SysOneT.*, ROW_NUMBER() OVER( ' + tempOrderBySQL + ' ) AS zPage_rn FROM ' + '    ( ' + tempSQL + ' ) SysOneT ' +
          ' ) SysOneT WHERE SysOneT.zPage_rn > ' + tempIStar.ToString + ' AND  SysOneT.zPage_rn <= ' + tempIEnd.ToString;
        QSQLInfo.FSQL := tempSQL;
        QSQLInfo.FPageField := 'zPage_rn';
      end;
    end
    else
    if QSQLInfo.FDriver.StartsWith(Driver_MySQL) then
    begin
      tempIStar := (QSQLInfo.FPageIndex - 1) * QSQLInfo.FPageSize;
      tempIEnd := tempIStar + QSQLInfo.FPageSize;
      lList.Add(' limit ' + tempIStar.ToString + ', ' + tempIEnd.ToString);
      QSQLInfo.FSQL := lList.Text;
    end
    else
    begin
      QSQLInfo.FErrMsg := '???????????????????????????[' + QSQLInfo.FDriver + ']???????????????????????????????????????!';
      exit;
    end;
  finally
    lList.Free;
  end;
  Result := True;
end;


initialization

finalization

end.
