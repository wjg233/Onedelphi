unit UniLoginController;

interface

uses
  system.StrUtils, system.SysUtils, Math, system.JSON, system.Threading, system.Classes,
  OneHttpController, OneHttpRouterManage, OneHttpCtxtResult, OneTokenManage, OneHttpConst,
  system.Generics.Collections, OneControllerResult, FireDAC.Comp.Client, Data.DB, OneGuID,
  OneMultipart;

type
  TLoginInfo = class
  private
    FloginCode: string; // ��½����
    FloginPass: string; // ��½����
    FloginZTCode: string; // ָ����½����
    FtokenID: string; // ����ȥ��TokenID
    FprivateKey: string; // ����ȥ��˽Կ
    FUserName: string; // ����ȥ���û�����
    // �����������Ϣ���Ѽӣ���ʾ��ֻ�Ǹ�demo
  published
    // ǰ��˲��������ؽ����дС�뱣֤һ�� ,��Ҫ����ΪʲôJSON�����ִ�Сд��,
    property loginCode: string read FloginCode write FloginCode;
    property loginPass: string read FloginPass write FloginPass;
    property loginZTCode: string read FloginZTCode write FloginZTCode;
    property tokenID: string read FtokenID write FtokenID;
    property privateKey: string read FprivateKey write FprivateKey;
    property userName: string read FUserName write FUserName;
  end;

  TUniLoginController = class(TOneControllerBase)
  public
    // ��½�ӿ�
    function Login(QLogin: TLoginInfo): TActionResult<TLoginInfo>;
    // �ǳ��ӿ�
    function LoginOut(QLogin: TLoginInfo): TActionResult<string>;
  end;

function CreateNewUniDemoController(QRouterItem: TOneRouterItem): TObject;

implementation

uses OneGlobal, OneZTManage;

function CreateNewUniDemoController(QRouterItem: TOneRouterItem): TObject;
var
  lController: TUniLoginController;
begin
  // �Զ��崴���������࣬����ᰴ TPersistentclass.create
  // ����Զ���һ����
  lController := TUniLoginController.Create;
  // ����RTTI��Ϣ
  lController.RouterItem := QRouterItem;
  result := lController;
end;

// ǰ��˲��������ؽ����дС�뱣֤һ�� ,��Ҫ����ΪʲôJSON�����ִ�Сд��,
function TUniLoginController.Login(QLogin: TLoginInfo): TActionResult<TLoginInfo>;
var
  lOneZTMange: TOneZTManage;
  lOneTokenManage: TOneTokenManage;
  lZTItem: TOneZTItem;
  lFDQuery: TFDQuery;
  lOneTokenItem: IOneTokenItem;
  lErrMsg: string;
begin
  result := TActionResult<TLoginInfo>.Create(true, false);
  lErrMsg := '';
  if QLogin.loginCode = '' then
  begin
    result.resultMsg := '�û����벻��Ϊ��';
    exit;
  end;
  if QLogin.loginPass = '' then
  begin
    result.resultMsg := '�û����벻��Ϊ��';
    exit;
  end;
  // ��֤�˺�����,�������ݿ�
  lOneZTMange := TOneGlobal.GetInstance().ZTManage;
  // ����Ϊ��ʱ,Ĭ��ȡ������,�����׵Ļ����Թ̶�һ�����״���
  lZTItem := lOneZTMange.LockZTItem(QLogin.loginZTCode, lErrMsg);
  if lZTItem = nil then
  begin
    result.resultMsg := lErrMsg;
    exit;
  end;
  try
    // �����׻�ȡ�ֳɵ�FDQuery,�Ѱ󶨺� connetion,Ҳ�����ͷ�
    lFDQuery := lZTItem.ADQuery;
    // ��߸ĳ�����û���
    lFDQuery.SQL.Text := 'select FUserID,FUserCode,FUserName,FUserPass from demo_user where FUserCode=:FUserCode';
    lFDQuery.Params[0].AsString := QLogin.loginCode;
    lFDQuery.Open;
    if lFDQuery.RecordCount = 0 then
    begin
      result.resultMsg := '��ǰ�û�[' + QLogin.loginCode + ']������,����';
      exit;
    end;
    if lFDQuery.RecordCount > 1 then
    begin
      result.resultMsg := '��ǰ�û�[' + QLogin.loginCode + ']�ظ�,����ϵ����Ա�������';
      exit;
    end;
    // Ϊһ��ʱҪ��֤����,ǰ��һ����MD5���ܵ�,���Ҳ�Ǳ���MD5���ܵ�
    if QLogin.loginPass.ToLower <> lFDQuery.FieldByName('FUserPass').AsString.ToLower then
    begin
      result.resultMsg := '��ǰ�û�[' + QLogin.loginCode + ']���벻��ȷ,����';
      exit;
    end;
    // ��ȷ����Token������ص�toeknID��˽Կ
    lOneTokenManage := TOneGlobal.GetInstance().TokenManage;
    // true����ͬ���˺Ź���token,���Խӿڹ����·�ֹ������ȥ
    lOneTokenItem := lOneTokenManage.AddLoginToken('uniapp', QLogin.loginCode, true, lErrMsg);
    if lOneTokenItem = nil then
    begin
      result.resultMsg := lErrMsg;
      exit;
    end;
    // ΪToken���������Ϣ
    lOneTokenItem.SetLoginUserCode(QLogin.loginCode);
    lOneTokenItem.SetZTCode(QLogin.loginZTCode); // ָ������
    lOneTokenItem.SetSysUserID(lFDQuery.FieldByName('FUserID').AsString);
    lOneTokenItem.SetSysUserName(lFDQuery.FieldByName('FUserName').AsString);
    lOneTokenItem.SetSysUserCode(lFDQuery.FieldByName('FUserCode').AsString);
    // ������Ϣ����
    result.resultData := TLoginInfo.Create;
    result.resultData.loginCode := QLogin.loginCode;
    result.resultData.tokenID := lOneTokenItem.tokenID;
    result.resultData.privateKey := lOneTokenItem.privateKey;
    result.resultData.userName := lFDQuery.FieldByName('FUserName').AsString;
    //
    result.SetResultTrue;
  finally
    // ����,�黹�غ���Ҫ
    lZTItem.UnLockWork;
  end;
end;

function TUniLoginController.LoginOut(QLogin: TLoginInfo): TActionResult<string>;
var
  lOneGlobal: TOneGlobal;
begin
  result := TActionResult<string>.Create(false, false);
  if QLogin.tokenID = '' then
  begin
    result.resultMsg := 'tokenIDΪ�����ϴ�tokenID';
    exit;
  end;
  lOneGlobal := TOneGlobal.GetInstance();
  lOneGlobal.TokenManage.RemoveToken(QLogin.tokenID);
  result.resultData := 'Tokenɾ���ɹ�';
  result.SetResultTrue();
end;

initialization

// ����ģʽע��
OneHttpRouterManage.GetInitRouterManage().AddHTTPSingleWork('/UniDemo/Login', TUniLoginController, 0, CreateNewUniDemoController);

finalization

end.
