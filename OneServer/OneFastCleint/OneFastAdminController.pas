unit OneFastAdminController;

interface

uses
  system.StrUtils, system.SysUtils, Math, system.JSON, system.Threading, system.Classes,
  OneHttpController, OneHttpRouterManage, OneHttpCtxtResult, OneTokenManage, OneHttpConst,
  system.Generics.Collections, OneControllerResult, FireDAC.Comp.Client, Data.DB, OneGuID,
  OneMultipart;

type
  TFastMenu = class(Tobject)
  private
    FMenuID: string;
    FChilds: TList<TFastMenu>;
  public
    constructor Create;
    destructor Destroy; override;
  end;

  TFastAdminController = class(TOneControllerBase)
  private
    function MenuRemoveByID(QMenu: TFastMenu; QMenuID: string): boolean;
  public
    function GetAdminMenu(): TActionResult<TFastMenu>;
  end;

implementation

uses OneGlobal, OneZTManage;

constructor TFastMenu.Create;
begin
  self.FChilds := TList<TFastMenu>.Create;
end;

destructor TFastMenu.Destroy;
var
  i: Integer;
begin
  for i := 0 to self.FChilds.Count - 1 do
  begin
    self.FChilds[i].Free;
  end;
  self.FChilds.Clear;
  self.FChilds.Free;
  inherited Destroy;
end;

function TFastAdminController.MenuRemoveByID(QMenu: TFastMenu; QMenuID: string): boolean;
var
  i: Integer;
begin
  Result := false;
  for i := 0 to QMenu.FChilds.Count - 1 do
  begin
    if QMenu.FChilds[i].FMenuID = QMenuID then
    begin
      // 明细child.child由child释放
      QMenu.FChilds[i].Free;
      Result := false;
      exit;
    end
    else
    begin
      if self.MenuRemoveByID(QMenu.FChilds[i], QMenuID) then
        exit;
    end;
  end;
end;

//
function TFastAdminController.GetAdminMenu(): TActionResult<TFastMenu>;
var
  lOneGlobal: TOneGlobal;
  lOneZTMange: TOneZTManage;
  lOneTokenManage: TOneTokenManage;
  lZTItem: TOneZTItem;
  lFDQuery: TFDQuery;
  lOneTokenItem: IOneTokenItem;
  lErrMsg: string;
  lNow: TDateTime;
  LTokenItem: IOneTokenItem;
  lDictMenus: TDictionary<string, TFastMenu>;
  //
  lTempMenu, lPMenu: TFastMenu;
  lFMenuID, lFPMenuID, lStatus: string;
begin
  Result := TActionResult<TFastMenu>.Create(true, false);
  lDictMenus := nil;
  LTokenItem := self.GetCureentToken(lErrMsg);
  if LTokenItem = nil then
  begin
    Result.SetTokenFail();
    exit;
  end;
  // 验证账号密码,比如数据库
  lOneZTMange := TOneGlobal.GetInstance().ZTManage;
  // 账套为空时,默认取主账套,多账套的话可以固定一个账套代码
  lZTItem := lOneZTMange.LockZTItem(LTokenItem.ZTCode, lErrMsg);
  if lZTItem = nil then
  begin
    Result.resultMsg := lErrMsg;
    exit;
  end;
  try
    lDictMenus := TDictionary<string, TFastMenu>.Create;
    Result.ResultData := TFastMenu.Create;
    // 从账套获取现成的FDQuery,已绑定好 connetion,也无需释放
    lFDQuery := lZTItem.ADQuery;
    // 这边改成你的用户表
    lFDQuery.SQL.Text := 'select FMenuID,FPMenuID,FMenuTreeCode,FMenuCaption,FMenuImgIndex,FMenuOpenMode,FMenuModuleCode,FMenuScript from onefast_menu order by  FMenuTreeCode asc ';
    lFDQuery.Open;
    lFDQuery.First;
    while not lFDQuery.Eof do
    begin
      lFMenuID := lFDQuery.FieldByName('FMenuID').AsString;
      lFPMenuID := lFDQuery.FieldByName('FPMenuID').AsString;
      lTempMenu := TFastMenu.Create;
      if lFPMenuID = '' then
      begin
        lDictMenus.Add(lFMenuID, lTempMenu);
        Result.ResultData.FChilds.Add(lTempMenu);
      end
      else
      begin
        lDictMenus.Add(lFMenuID, lTempMenu);
        if lDictMenus.TryGetValue(lFPMenuID, lPMenu) then
        begin
          lPMenu.FChilds.Add(lTempMenu)
        end
        else
        begin
          Result.ResultData.FChilds.Add(lTempMenu);
        end;
      end;
      lFDQuery.Next;
    end;
    // 角色启用禁用
    lFDQuery := lZTItem.ADQuery;
    lFDQuery.SQL.Text := 'select ' + ' B.FStatus,C.FMenuID,C.FPMenuID,C.FMenuTreeCode,C.FMenuCaption,C.FMenuImgIndex,C.FMenuOpenMode,C.FMenuModuleCode,C.FMenuScript ' + ' from onefast_admin_role A ' +
      ' inner join onefast_role_menu B on(A.FRoleID=B.FRoleID) ' + ' inner join onefast_menu C on(B.FMenuID=C.FMenuID) ' + ' order by C.FMenuTreeCode asc';
    lFDQuery.Open;
    // 多角色组合权限,有一个启用就算启用
    lDictMenus.Clear;
    lFDQuery.First;
    while not lFDQuery.Eof do
    begin
      lStatus := lFDQuery.FieldByName('FStatus').AsString;
      lFMenuID := lFDQuery.FieldByName('FMenuID').AsString;
      if lStatus = '禁用' then
      begin
        lDictMenus.Add(lFMenuID, nil);
      end;
      lFDQuery.Next;
    end;

    lFDQuery.First;
    while not lFDQuery.Eof do
    begin
      lStatus := lFDQuery.FieldByName('FStatus').AsString;
      lFMenuID := lFDQuery.FieldByName('FMenuID').AsString;
      if lStatus = '启用' then
      begin
        if lDictMenus.ContainsKey(lFMenuID) then
        begin
          lDictMenus.Remove(lFMenuID);
        end;
      end;
      lFDQuery.Next;
    end;
    // 删除禁用的
    for lFMenuID in lDictMenus.Keys do
    begin
      self.MenuRemoveByID(Result.ResultData, lFMenuID);
    end;
    Result.SetResultTrue;
  finally
    // 解锁,归还池很重要
    lZTItem.UnLockWork;
    lDictMenus.Clear;
    lDictMenus.Free;
  end;
end;

end.
