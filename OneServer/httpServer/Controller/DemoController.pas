unit DemoController;

interface

uses OneHttpController, OneHttpPublic, OneHttpRouterManage, System.SysUtils,
  System.Generics.Collections, System.Contnrs, System.Classes,
  FireDAC.Comp.Client, Data.DB;

type
  TPersonDemo = class
  private
    FaName: string;
    FAag: integer;
  public
    property name: string read FaName write FaName;
    property age: integer read FAag write FAag;
  end;

type
  TPersonResult = class
  private
    FPerson: TPersonDemo;
    FResultCode: string;
    FReslutMsg: string;
  public
    // Ȧ���࣬��Ҫ�����ͷ�ʱ�ͷ� FPerson
    constructor Create;
    destructor Destroy; override;
  public
    property resultCode: string read FResultCode write FResultCode;
    property resultMsg: string read FReslutMsg write FReslutMsg;
    property person: TPersonDemo read FPerson write FPerson;
  end;

  TPersonListResult = class
  private
    FPersons: TList<TPersonDemo>;
    FResultCode: string;
    FReslutMsg: string;
  public
    // Ȧ���࣬��Ҫ�����ͷ�ʱ�ͷ� FPerson
    constructor Create;
    destructor Destroy; override;
  public
    property resultCode: string read FResultCode write FResultCode;
    property resultMsg: string read FReslutMsg write FReslutMsg;
    property persons: TList<TPersonDemo> read FPersons write FPersons;
  end;

  TDemoController = class(TOneControllerBase)
  public
    // ���ս��:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: "��ӭ����HelloWorld"}
    procedure HelloWorld(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // ���ս��ֻ����ı�:��ӭ����HelloWorld
    procedure HelloWorldStr(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // ���ս��:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: {name: "������flm123", aag: 32}}
    procedure person(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // �޲�����������,���Ҫ�õ����Ʋ� HTTPCtxt,HTTPResult�����Ƕ���ģʽ
    procedure TestNoParam();
    // ����������ֵ
    function GetStr(): string;
    function GetInt(): integer;
    // ���ؽ�� {name: "������flm123", age: 32}
    function GetPerson(): TPersonDemo;
    // ���ؽ�� [{name: "������0", age: 32}, {name: "������1", age: 32}]
    function GetPersonListT(): TList<TPersonDemo>;
    function GetPersonListBigT(): TList<TPersonDemo>;
    // ���ؽ�� [{name: "������0", age: 32}, {name: "������1", age: 32}]
    function GetPersonObjListT(): TObjectList<TPersonDemo>;
    // TListֻ֧�� item�Ƕ���
    // �����÷��� TList<T>,֧�ֵĸ���
    // ���ؽ�� [{name: "������0", age: 32}, {name: "������1", age: 32}]
    function GetPersonList(): TList;
    // �����÷��� TList<T>,֧�ֵĸ���
    // ���ؽ�� [{name: "������0", age: 32}, {name: "������1", age: 32}]
    function GetPersonObjList(): TObjectList;
    // ���ؽ�� [0,1,2,3,4,5]
    function GetIntListT(): TList<integer>;
    // ����ֵ��DataSet,���ؽ�� [{name: "������0", age: 32}, {name: "������1", age: 32}]
    function GetDataSet(): TFDMemTable;

    // ��OneGet��ͷֻ֧��get����,����nameȡ��url����
    function OneGetName(name: string): string;
    // ��OneGet��ͷֻ֧��get����,����name��ageȡ��url����
    function OneGetPerson(name: string; age: integer): TPersonDemo;
    // ��OnePost��ͷֻ֧��post����,����name,ageȡ���ύ��JSON����{name: "������1", age: 32}
    function OnePostPerson(name: string; age: integer): TPersonDemo;
    // ��OnePost��ͷֻ֧��post����,����name,ageȡ���ύ��JSON����{name: "������1", age: 32}������ TPersonDemo
    // �׳�ؓ؟ጷŅ���person��������ጉ�
    function OnePostPersonClass(person: TPersonDemo): TPersonDemo;
    // ��OnePost��ͷֻ֧��post����,��ϲ���person,nameȡ���ύ��JSON����{person:{name: "������1", age: 32},name:"������2"}������ TPersonDemo
    // �׳�ؓ؟ጷŅ���person��������ጉ�
    function OnePostPersonB(person: TPersonDemo; name: string): TPersonDemo;
    // �ύһ������ [{"name":"flm","age":18},{"name":"flm2","age":18},{"name":"flm3","age":18}]
    // ���ؽ��:[{"name":"flm","age":18},{"name":"flm2","age":18},{"name":"flm3","age":18}]
    function OnePostPersonList(persons: TList<TPersonDemo>): TList<TPersonDemo>;
    // Ȧ���� TPersonResult�����ж�������
    function OneGetPersonResult(): TPersonResult;
    // Ȧ���� �ύ������ TPersonResult�����ж�������
    // �� TPersonResult.createҪ�ȴ����� FPerson :=  TPersonDemo.Create; ���ɽ��ղ���
    function OnePostPersonResult(personResult: TPersonResult): string;

    // Ȧ���� TPersonResult�����ж�������
    function OneGetPersonListResult(): TPersonListResult;
    // Ȧ���� �ύ������ TPersonResult�����ж�������
    // �� TPersonResult.createҪ�ȴ����� FPerson :=  TPersonDemo.Create; ���ɽ��ղ���
    function OnePostPersonListResult(personListResult
      : TPersonListResult): string;
  end;

function CreateNewDemoController(QRouterItem: TOneRouterItem): TObject;
// ��������ע��
procedure HelloWorldEven(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);

implementation

constructor TPersonResult.Create;
begin
  inherited Create;
  // ���JSONת��,��ҪԤ�ȴ�������
  FPerson := TPersonDemo.Create;
end;

destructor TPersonResult.Destroy;
begin
  if FPerson <> nil then
  begin
    FPerson.Free;
    FPerson := nil;
  end;
  inherited Destroy;
end;

constructor TPersonListResult.Create;
begin
  inherited Create;
  self.FPersons := TList<TPersonDemo>.Create;
end;

destructor TPersonListResult.Destroy;
var
  i: integer;
begin
  if self.FPersons <> nil then
  begin
    for i := 0 to FPersons.Count - 1 do
    begin
      FPersons[i].Free;
    end;
    FPersons.Clear;
    FPersons.Free;
  end;
  inherited Destroy;
end;

procedure TDemoController.HelloWorld(QHTTPCtxt: THTTPCtxt;
  QHTTPResult: THTTPResult);
begin
  // Ĭ��JSON�����ResultData=QHTTPResult.ResultOut;
  // ���ս��:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: "��ӭ����HelloWorld"}
  QHTTPResult.ResultOut := '��ӭ����HelloWorld';
  QHTTPResult.SetHTTPResultTrue();
end;

procedure TDemoController.HelloWorldStr(QHTTPCtxt: THTTPCtxt;
  QHTTPResult: THTTPResult);
begin
  QHTTPResult.ResultOut := '��ӭ����HelloWorld';
  // ���ս��ֻ����ı�:��ӭ����HelloWorld
  QHTTPResult.ResultOutMode := THTTPResultMode.TEXT;
  QHTTPResult.SetHTTPResultTrue();
end;

procedure TDemoController.person(QHTTPCtxt: THTTPCtxt;
  QHTTPResult: THTTPResult);
var
  lPersonDemo: TPersonDemo;
begin
  // Ĭ��Json���,ResultData= QHTTPResult.ResultObj;
  // ���ս��:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: {name: "������flm123", aag: 32}}
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.name := '������flm123';
  lPersonDemo.age := 32;
  // lPersonDemoע�������ͷ�,���׳� THTTPResult.Destroy ʱ���ͷ� ResultObj����
  QHTTPResult.ResultObj := lPersonDemo;
  QHTTPResult.SetHTTPResultTrue();
end;

// �����ַ���
function TDemoController.GetStr(): string;
begin
  result := '��ӭ����������������';
end;

// ��������
function TDemoController.GetInt(): integer;
begin
  result := 10000;
end;

// ����һ������
function TDemoController.GetPerson(): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.name := '������flm123';
  lPersonDemo.age := 32;
  result := lPersonDemo;
end;

function TDemoController.GetPersonListT(): TList<TPersonDemo>;
var
  lPersonDemo: TPersonDemo;
  lList: TList<TPersonDemo>;
  i: integer;
begin
  lList := TList<TPersonDemo>.Create;
  for i := 0 to 9 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := '������' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  result := lList;
end;

function TDemoController.GetPersonListBigT(): TList<TPersonDemo>;
var
  lPersonDemo: TPersonDemo;
  lList: TList<TPersonDemo>;
  i: integer;
begin
  lList := TList<TPersonDemo>.Create;
  // һ�η���10������
  for i := 0 to 99999 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := '������' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  result := lList;
end;

function TDemoController.GetPersonObjListT(): TObjectList<TPersonDemo>;
var
  lPersonDemo: TPersonDemo;
  lList: TObjectList<TPersonDemo>;
  i: integer;
begin
  lList := TObjectList<TPersonDemo>.Create;
  for i := 0 to 9 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := '������' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  result := lList;
end;

function TDemoController.GetPersonList(): TList;
var
  lPersonDemo: TPersonDemo;
  lList: TList;
  i: integer;
begin
  lList := TList.Create;
  for i := 0 to 9 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := '������' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  result := lList;
end;

function TDemoController.GetPersonObjList(): TObjectList;
var
  lPersonDemo: TPersonDemo;
  lList: TObjectList;
  i: integer;
begin
  lList := TObjectList.Create;
  for i := 0 to 9 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := '������' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  result := lList;
end;

function TDemoController.GetIntListT(): TList<integer>;
var
  lList: TList<integer>;
  i: integer;
begin
  lList := TList<integer>.Create;
  for i := 0 to 9 do
  begin
    lList.Add(i);
  end;
  result := lList;
end;

// ����ֵ��DataSet
function TDemoController.GetDataSet(): TFDMemTable;
var
  i: integer;
begin
  result := TFDMemTable.Create(nil);
  result.FieldDefs.Add('name', ftString, 20, false);
  result.FieldDefs.Add('age', ftInteger, 0, True);
  result.CreateDataSet();
  for i := 0 to 9 do
  begin
    result.Append;
    result.FieldByName('name').AsString := 'flm' + i.ToString();
    result.FieldByName('age').AsInteger := i;
    result.Post;
  end;
end;

// �޲���������ģʽ
procedure TDemoController.TestNoParam();
var
  lUrl: string;
begin
  // ����ģʽ  HTTPCtxt,HTTPResult���Ƕ�����
  lUrl := self.HTTPCtxt.URL;
  self.HTTPResult.ResultOut := lUrl;
  self.HTTPResult.SetHTTPResultTrue();
end;

function TDemoController.OneGetName(name: string): string;
begin
  result := '�ϴ���Url����name=' + name;
end;

function TDemoController.OneGetPerson(name: string; age: integer): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.name := name;
  lPersonDemo.age := age;
  result := lPersonDemo;
end;

// ��OnePost��ͷֻ֧��post����,����name,ageȡ���ύ��JSON����{name: "������1", age: 32}
function TDemoController.OnePostPerson(name: string; age: integer): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.name := name;
  lPersonDemo.age := age;
  result := lPersonDemo;
end;

function TDemoController.OnePostPersonClass(person: TPersonDemo): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  //
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.name := person.name;
  lPersonDemo.age := person.age;
  // person��lPersonDemo �׳�ؓ؟ጷ�,�����ֶ��ͷ�
  result := lPersonDemo;
end;

// ��ϲ���
// ��OnePost��ͷֻ֧��post����,��ϲ���person,nameȡ���ύ��JSON����{person:{name: "������1", age: 32},name:"������2"}������ TPersonDemo
function TDemoController.OnePostPersonB(person: TPersonDemo; name: string)
  : TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  //
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.name := person.name + '_' + name;
  lPersonDemo.age := person.age;
  // person��lPersonDemo �׳�ؓ؟ጷ�,�����ֶ��ͷ�
  result := lPersonDemo;
end;

function TDemoController.OnePostPersonList(persons: TList<TPersonDemo>)
  : TList<TPersonDemo>;
var
  lPersonDemo: TPersonDemo;
  i: integer;
begin
  result := TList<TPersonDemo>.Create;
  for i := 0 to persons.Count - 1 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := persons[i].name;
    lPersonDemo.age := persons[i].age;
    result.Add(lPersonDemo);
  end;
end;

function TDemoController.OneGetPersonResult(): TPersonResult;
begin
  result := TPersonResult.Create;
  result.resultCode := '123';
  result.resultMsg := '������';
  // �ǵ���д TPersonResult �ͷ�ʱҪ�ж� person�ǲ���Ϊnil
  // �׳�����ֻ���� TPersonResult.free;
  result.person.name := 'flm';
  result.person.age := 19;
end;

function TDemoController.OnePostPersonResult(personResult
  : TPersonResult): string;
begin
  result := '�յ����ݳɹ� code->' + personResult.resultCode;
  if personResult.person <> nil then
  begin
    result := result + ';name->' + personResult.person.name;
  end;
end;

function TDemoController.OneGetPersonListResult(): TPersonListResult;
var
  lPersonDemo: TPersonDemo;
  i: integer;
begin
  result := TPersonListResult.Create;
  result.resultCode := '123';
  result.resultMsg := '������';
  for i := 0 to 9 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.name := 'flm';
    lPersonDemo.age := 18;
    result.persons.Add(lPersonDemo)
  end;

end;

function TDemoController.OnePostPersonListResult(personListResult
  : TPersonListResult): string;
begin
  result := '�յ����ݳɹ� code->' + personListResult.resultCode;
  if personListResult.persons <> nil then
  begin
    result := result + ';count->' + personListResult.persons.Count.ToString();
  end;
end;

function CreateNewDemoController(QRouterItem: TOneRouterItem): TObject;
var
  lController: TDemoController;
begin
  // �Զ��崴���������࣬����ᰴ TPersistentclass.create
  // ����Զ���һ����
  lController := TDemoController.Create;
  // ����RTTI��Ϣ
  lController.RouterItem := QRouterItem;
  result := lController;
end;

procedure HelloWorldEven(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
begin
  QHTTPResult.ResultOut := '��ӭ����HelloWorldEven';
end;

// ע�ᵽ·��
initialization

// ע�⣬·������ ��Ҫһ����������ж���ע���������
// ����ģʽע��
OneHttpRouterManage.GetInitRouterManage().AddHTTPPoolWork('DemoA',
  TDemoController, 100, CreateNewDemoController);
// ����ģʽע��
OneHttpRouterManage.GetInitRouterManage().AddHTTPSingleWork('DemoB',
  TDemoController, 100, CreateNewDemoController);
// ����ע��
OneHttpRouterManage.GetInitRouterManage().AddHTTPEvenWork('DemoEven',
  HelloWorldEven, 10);

finalization

end.
