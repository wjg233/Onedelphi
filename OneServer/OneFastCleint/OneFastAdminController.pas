﻿unit OneFastAdminController;

interface

uses
  system.StrUtils, system.SysUtils, Math, system.JSON, system.Threading, system.Classes,
  OneHttpController, OneHttpRouterManage, OneHttpCtxtResult, OneTokenManage, OneHttpConst,
  system.Generics.Collections, OneControllerResult, FireDAC.Comp.Client, Data.DB, OneGuID,
  OneMultipart;

type
  TFastMenu = class(Tobject)
  private
    FMenuID_: string;
    FPMenuID_: string;
    FMenuTreeCode_: string;
    FMenuCaption_: string;
    FMenuImgIndex_: integer;
    FMenuOpenMode_: string;
    FMenuModuleCode_: string;
    FMenuScript_: string;
    FChilds_: TList<TFastMenu>;
  public
    constructor Create;
    destructor Destroy; override;
  published
    property FMenuID: string read FMenuID_ write FMenuID_;
    property FPMenuID: string read FPMenuID_ write FPMenuID_;
    property FMenuTreeCode: string read FMenuTreeCode_ write FMenuTreeCode_;
    property FMenuCaption: string read FMenuCaption_ write FMenuCaption_;
    property FMenuImgIndex: integer read FMenuImgIndex_ write FMenuImgIndex_;
    property FMenuOpenMode: string read FMenuOpenMode_ write FMenuOpenMode_;
    property FMenuModuleCode: string read FMenuModuleCode_ write FMenuModuleCode_;
    property FMenuScript: string read FMenuScript_ write FMenuScript_;
    property FChilds: TList<TFastMenu> read FChilds_ write FChilds_;
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
  i: integer;
begin
  for i := 0 to self.FChilds.Count - 1 do
  begin
    self.FChilds[i].Free;
  end;
  self.FChilds.Clear;
  self.FChilds.Free;
  inherited Destroy;
end;

function CreateNewFastAdminController(QRouterItem: TOneRouterItem): Tobject;
var
  lController: TFastAdminController;
begin
  // 自定义创建控制器类，否则会按 TPersistentclass.create
  // 最好自定义一个好
  lController := TFastAdminController.Create;
  // 挂载RTTI信息
  lController.RouterItem := QRouterItem;
  result := lController;
end;

function TFastAdminController.MenuRemoveByID(QMenu: TFastMenu; QMenuID: string): boolean;
var
  i: integer;
begin
  result := false;
  for i := 0 to QMenu.FChilds.Count - 1 do
  begin
    if QMenu.FChilds[i].FMenuID = QMenuID then
    begin
      // 明细child.child由child释放
      QMenu.FChilds[i].Free;
      result := false;
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
  result := TActionResult<TFastMenu>.Create(true, false);
  lDictMenus := nil;
  LTokenItem := self.GetCureentToken(lErrMsg);
  if LTokenItem = nil then
  begin
    result.SetTokenFail();
    exit;
  end;
  // 验证账号密码,比如数据库
  lOneZTMange := TOneGlobal.GetInstance().ZTManage;
  // 账套为空时,默认取主账套,多账套的话可以固定一个账套代码
  lZTItem := lOneZTMange.LockZTItem(LTokenItem.ZTCode, lErrMsg);
  if lZTItem = nil then
  begin
    result.resultMsg := lErrMsg;
    exit;
  end;
  try
    lDictMenus := TDictionary<string, TFastMenu>.Create;
    result.ResultData := TFastMenu.Create;
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
      lTempMenu.FMenuID := lFMenuID;
      lTempMenu.FPMenuID := lFPMenuID;
      lTempMenu.FMenuTreeCode := lFDQuery.FieldByName('FMenuTreeCode').AsString;
      lTempMenu.FMenuCaption := lFDQuery.FieldByName('FMenuCaption').AsString;
      lTempMenu.FMenuImgIndex := lFDQuery.FieldByName('FMenuImgIndex').AsInteger;
      lTempMenu.FMenuOpenMode := lFDQuery.FieldByName('FMenuOpenMode').AsString;
      lTempMenu.FMenuModuleCode := lFDQuery.FieldByName('FMenuModuleCode').AsString;
      lTempMenu.FMenuScript := lFDQuery.FieldByName('FMenuScript').AsString;
      if lFPMenuID = '' then
      begin
        lDictMenus.Add(lFMenuID, lTempMenu);
        result.ResultData.FChilds.Add(lTempMenu);
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
          result.ResultData.FChilds.Add(lTempMenu);
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
      self.MenuRemoveByID(result.ResultData, lFMenuID);
    end;
    result.SetResultTrue;
  finally
    // 解锁,归还池很重要
    lZTItem.UnLockWork;
    lDictMenus.Clear;
    lDictMenus.Free;
  end;
end;

initialization

// 单例模式注册
OneHttpRouterManage.GetInitRouterManage().AddHTTPSingleWork('/FastClient/Admin', TFastAdminController, 0, CreateNewFastAdminController);

finalization

end.
