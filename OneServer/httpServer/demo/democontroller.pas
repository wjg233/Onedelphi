unit DemoController;

{$mode DELPHI}{$H+}
interface

uses OneHttpController, OneHttpCtxtResult, OneHttpRouterManage, SysUtils,
  Generics.Collections, Contnrs, Classes, DB, BufDataset, Rtti, OneSerialization;

type
  TPersonResult = class
  private
    FPerson: TPersonDemo;
    FResultCode: string;
    FReslutMsg: string;
  public
    // 圈套类，需要在类释放时释放 FPerson
    constructor Create;
    destructor Destroy; override;
    //只有 published rtti才能读取到
  published
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
    // 圈套类，需要在类释放时释放 FPerson
    constructor Create;
    destructor Destroy; override;
    //只有 published rtti才能读取到
  published
    property resultCode: string read FResultCode write FResultCode;
    property resultMsg: string read FReslutMsg write FReslutMsg;
    property persons: TList<TPersonDemo> read FPersons write FPersons;
  end;

  {$M+}
  IDemoController = interface
    ['{4FE8A25E-7DE4-4E39-9716-6E771F7BD629}']
    procedure HelloWorld(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // 最终结果只输出文本:欢迎来到HelloWorld
    procedure HelloWorldStr(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // 最终结果:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: {name: "范联满flm123", aag: 32}}
    procedure person(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // 无参数方法调用,如果要用到控制层 HTTPCtxt,HTTPResult必需是多例模式
    procedure TestNoParam();
    // 代函数返回值
    function GetStr(): string;
    function GetInt(): integer;
    // 返回结果 {name: "范联满flm123", age: 32}
    function GetPerson(): TPersonDemo;
    //laz不支持结构体输出,自已用JSON输出
    //function GetPersonrecord(): TPersonrecord;
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonListT(): TList<TPersonDemo>;
    function GetPersonListBigT(): TList<TPersonDemo>;
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonObjListT(): TObjectList<TPersonDemo>;
    // TList只支持 item是对象
    // 建议用泛型 TList<T>,支持的更好
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonList(): TList;
    // 建议用泛型 TList<T>,支持的更好
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonObjList(): TObjectList;
    // 返回结果 [0,1,2,3,4,5]
    function GetIntListT(): TList<integer>;
    // 以OneGet开头只支持get访问,参数name取自url参数
    function OneGetName(Name: string): string;
    // 以OneGet开头只支持get访问,参数name，age取自url参数
    function OneGetPerson(Name: string; age: integer): TPersonDemo;
    // 以OnePost开头只支持post访问,参数name,age取自提交的JSON数据{name: "范联满1", age: 32}
    function OnePostPerson(Name: string; age: integer): TPersonDemo;
    // 以OnePost开头只支持post访问,参数name,age取自提交的JSON数据{name: "范联满1", age: 32}反射成類 TPersonDemo
    // 底程負責釋放參數person用完自已釋壙
    function OnePostPersonClass(person: TPersonDemo): TPersonDemo;
    // 以OnePost开头只支持post访问,混合参数person,name取自提交的JSON数据{person:{name: "范联满1", age: 32},name:"范联满2"}反射成類 TPersonDemo
    // 底程負責釋放參數person用完自已釋壙
    function OnePostPersonB(person: TPersonDemo; Name: string): TPersonDemo;
    // 提交一个数组 [{"name":"flm","age":18},{"name":"flm2","age":18},{"name":"flm3","age":18}]
    // 返回结果:[{"name":"flm","age":18},{"name":"flm2","age":18},{"name":"flm3","age":18}]
    function OnePostPersonList(persons: TList<TPersonDemo>): TList<TPersonDemo>;
    // 圈套类 TPersonResult对象含有对象属性
    function OneGetPersonResult(): TPersonResult;
    // 圈套类 提交的数据 TPersonResult对象含有对象属性
    // 在 TPersonResult.create要先创建好 FPerson :=  TPersonDemo.Create; 方可接收参数
    function OnePostPersonResult(personResult: TPersonResult): string;

    // 圈套类 TPersonResult对象含有对象属性
    function OneGetPersonListResult(): TPersonListResult;
    // 圈套类 提交的数据 TPersonResult对象含有对象属性
    // 在 TPersonResult.create要先创建好 FPerson :=  TPersonDemo.Create; 方可接收参数
    function OnePostPersonListResult(personListResult: TPersonListResult): string;
  end;

  {$M-}


  TDemoController = class(TOneControllerBase, IDemoController)
  protected

  public
    //各个方法实现
    function DoInvoke(QRttiMethod: TRttiMethod; const aArgs: array of TValue): TValue;
      override;
    // 最终结果:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: "欢迎来到HelloWorld"}
    procedure HelloWorld(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // 最终结果只输出文本:欢迎来到HelloWorld
    procedure HelloWorldStr(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // 最终结果:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: {name: "范联满flm123", aag: 32}}
    procedure person(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
    // 无参数方法调用,如果要用到控制层 HTTPCtxt,HTTPResult必需是多例模式
    procedure TestNoParam();
    // 代函数返回值
    function GetStr(): string;
    function GetInt(): integer;
    // 返回结果 {name: "范联满flm123", age: 32}
    function GetPerson(): TPersonDemo;
    //function GetPersonrecord(): TPersonrecord;
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonListT(): TList<TPersonDemo>;
    function GetPersonListBigT(): TList<TPersonDemo>;
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonObjListT(): TObjectList<TPersonDemo>;
    // TList只支持 item是对象
    // 建议用泛型 TList<T>,支持的更好
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonList(): TList;
    // 建议用泛型 TList<T>,支持的更好
    // 返回结果 [{name: "范联满0", age: 32}, {name: "范联满1", age: 32}]
    function GetPersonObjList(): TObjectList;
    // 返回结果 [0,1,2,3,4,5]
    function GetIntListT(): TList<integer>;
    // 以OneGet开头只支持get访问,参数name取自url参数
    function OneGetName(Name: string): string;
    // 以OneGet开头只支持get访问,参数name，age取自url参数
    function OneGetPerson(Name: string; age: integer): TPersonDemo;
    // 以OnePost开头只支持post访问,参数name,age取自提交的JSON数据{name: "范联满1", age: 32}
    function OnePostPerson(Name: string; age: integer): TPersonDemo;
    // 以OnePost开头只支持post访问,参数name,age取自提交的JSON数据{name: "范联满1", age: 32}反射成類 TPersonDemo
    // 底程負責釋放參數person用完自已釋壙
    function OnePostPersonClass(person: TPersonDemo): TPersonDemo;
    // 以OnePost开头只支持post访问,混合参数person,name取自提交的JSON数据{person:{name: "范联满1", age: 32},name:"范联满2"}反射成類 TPersonDemo
    // 底程負責釋放參數person用完自已釋壙
    function OnePostPersonB(person: TPersonDemo; Name: string): TPersonDemo;
    // 提交一个数组 [{"name":"flm","age":18},{"name":"flm2","age":18},{"name":"flm3","age":18}]
    // 返回结果:[{"name":"flm","age":18},{"name":"flm2","age":18},{"name":"flm3","age":18}]
    function OnePostPersonList(persons: TList<TPersonDemo>): TList<TPersonDemo>;
    // 圈套类 TPersonResult对象含有对象属性
    function OneGetPersonResult(): TPersonResult;
    // 圈套类 提交的数据 TPersonResult对象含有对象属性
    // 在 TPersonResult.create要先创建好 FPerson :=  TPersonDemo.Create; 方可接收参数
    function OnePostPersonResult(personResult: TPersonResult): string;

    // 圈套类 TPersonResult对象含有对象属性
    function OneGetPersonListResult(): TPersonListResult;
    // 圈套类 提交的数据 TPersonResult对象含有对象属性
    // 在 TPersonResult.create要先创建好 FPerson :=  TPersonDemo.Create; 方可接收参数
    function OnePostPersonListResult(personListResult: TPersonListResult): string;
  end;


function CreateNewDemoController(QRouterItem: TOneRouterItem): TObject;
// 方法类型注册
procedure HelloWorldEven(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);

implementation

constructor TPersonResult.Create;
begin
  inherited Create;
  // 如果JSON转类,需要预先创建属性
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

function TDemoController.DoInvoke(QRttiMethod: TRttiMethod;
  const aArgs: array of TValue): TValue;
var
  lDemoController: IDemoController;
  lMethodName: string;
begin
  Result := nil;
  {$if defined(CPUI386) or (defined(CPUX86_64) and defined(WIN64))}
  //转化成接口
  lDemoController := self as IDemoController;
  //进行接口RTTI代理
  Result := QRttiMethod.Invoke(lDemoController, aArgs);
  exit;
  {$endif}
  //其它CPU硬件不支持,那么只能手写一个一个判断
  //希望后面加强其它CPU的反射,那么就不会这么麻烦了
  lMethodName := QRttiMethod.Name;
  if lMethodName = 'HelloWorld' then
  begin
    self.HelloWorld(THTTPCtxt(aArgs[0].AsObject), THTTPResult(aArgs[1].AsObject));
  end
  else
  if lMethodName = 'HelloWorldStr' then
  begin
    self.HelloWorldStr(THTTPCtxt(aArgs[0].AsObject), THTTPResult(aArgs[1].AsObject));
  end
  else
  if lMethodName = 'person' then
  begin
    self.person(THTTPCtxt(aArgs[0].AsObject), THTTPResult(aArgs[1].AsObject));
  end
  else
  if lMethodName = 'GetStr' then
  begin
    Result := self.GetStr();
  end
  else
  if lMethodName = 'GetInt' then
  begin
    Result := self.GetInt();
  end
  else
  if lMethodName = 'GetPerson' then
  begin
    Result := self.GetPerson();
  end
  else
  if lMethodName = 'GetPersonListT' then
  begin
    Result := self.GetPersonListT();
  end
  else
  if lMethodName = 'GetPersonListBigT' then
  begin
    Result := self.GetPersonListBigT();
  end
  else
  if lMethodName = 'GetPersonObjListT' then
  begin
    Result := self.GetPersonObjListT();
  end
  else
  if lMethodName = 'GetPersonList' then
  begin
    Result := self.GetPersonList();
  end
  else
  if lMethodName = 'GetPersonObjList' then
  begin
    Result := self.GetPersonObjList();
  end
  else
  if lMethodName = 'GetIntListT' then
  begin
    Result := self.GetIntListT();
  end
  else
  if lMethodName = 'TestNoParam' then
  begin
    self.TestNoParam();
  end
  else
  if lMethodName = 'OneGetName' then
  begin
    Result := self.OneGetName(aArgs[0].AsString);
  end
  else
  if lMethodName = 'OneGetPerson' then
  begin
    Result := self.OneGetPerson(aArgs[0].AsString, aArgs[1].AsInteger);
  end
  else
  if lMethodName = 'OnePostPerson' then
  begin
    Result := self.OnePostPerson(aArgs[0].AsString, aArgs[1].AsInteger);
  end
  else
  if lMethodName = 'OnePostPersonClass' then
  begin
    Result := self.OnePostPersonClass(TPersonDemo(aArgs[0].AsObject));
  end
  else
  if lMethodName = 'OnePostPersonB' then
  begin
    Result := self.OnePostPersonB(TPersonDemo(aArgs[0].AsObject), aArgs[1].AsString);
  end
  else
  if lMethodName = 'OnePostPersonList' then
  begin
    Result := self.OnePostPersonList(TList<TPersonDemo>(aArgs[0].AsObject));
  end
  else
  if lMethodName = 'OneGetPersonResult' then
  begin
    Result := self.OneGetPersonResult();
  end
  else
  if lMethodName = 'OnePostPersonResult' then
  begin
    Result := self.OnePostPersonResult(TPersonResult(aArgs[0].AsObject));
  end
  else
  if lMethodName = 'OneGetPersonListResult' then
  begin
    Result := self.OneGetPersonListResult();
  end
  else
  if lMethodName = 'OnePostPersonListResult' then
  begin
    Result := self.OnePostPersonListResult(TPersonListResult(aArgs[0].AsObject));
  end
  else
  begin
    raise Exception.Create(lMethodName + '未关联方法,请注意方法大小写');
  end;
end;

procedure TDemoController.HelloWorld(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
begin
  // 默认JSON输出，ResultData=QHTTPResult.ResultOut;
  // 最终结果:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: "欢迎来到HelloWorld"}
  QHTTPResult.ResultOut := '欢迎来到HelloWorld';
  QHTTPResult.SetHTTPResultTrue();
end;

procedure TDemoController.HelloWorldStr(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
begin
  QHTTPResult.ResultOut := '欢迎来到HelloWorld';
  // 最终结果只输出文本:欢迎来到HelloWorld
  QHTTPResult.ResultOutMode := THTTPResultMode.Text;
  QHTTPResult.SetHTTPResultTrue();
end;

procedure TDemoController.person(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
var
  lPersonDemo: TPersonDemo;
begin
  // 默认Json输出,ResultData= QHTTPResult.ResultObj;
  // 最终结果:{ResultCode: "0001", ResultMsg: "", ResultCount: 0, ResultData: {name: "范联满flm123", aag: 32}}
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.Name := '范联满flm123';
  lPersonDemo.age := 32;
  // lPersonDemo注意无需释放,当底程 THTTPResult.Destroy 时会释放 ResultObj对象
  QHTTPResult.ResultObj := lPersonDemo;
  QHTTPResult.SetHTTPResultTrue();
end;

// 返回字符串
function TDemoController.GetStr(): string;
begin
  Result := '欢迎来到函数返回世界';
end;

// 返回整型
function TDemoController.GetInt(): integer;
begin
  Result := 10000;
end;

// 返回一个对象
function TDemoController.GetPerson(): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.Name := '范联满flm123';
  lPersonDemo.age := 32;
  Result := lPersonDemo;
end;

//function TDemoController.GetPersonrecord(): TPersonrecord;
//begin
//  Result.Name := '范联满';
//  Result.age := 32;
//end;

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
    lPersonDemo.Name := '范联满' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  Result := lList;
end;

function TDemoController.GetPersonListBigT(): TList<TPersonDemo>;
var
  lPersonDemo: TPersonDemo;
  lList: TList<TPersonDemo>;
  i: integer;
begin
  lList := TList<TPersonDemo>.Create;
  // 一次返回10万数据
  for i := 0 to 99999 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.Name := '范联满' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  Result := lList;
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
    lPersonDemo.Name := '范联满' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  Result := lList;
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
    lPersonDemo.Name := '范联满' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  Result := lList;
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
    lPersonDemo.Name := '范联满' + i.ToString;
    lPersonDemo.age := 32;
    lList.Add(lPersonDemo);
  end;
  Result := lList;
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
  Result := lList;
end;

// 无参数，多例模式
procedure TDemoController.TestNoParam();
var
  lUrl: string;
begin
  // 多例模式  HTTPCtxt,HTTPResult多是独立的
  lUrl := self.HTTPCtxt.URL;
  self.HTTPResult.ResultOut := lUrl;
  self.HTTPResult.SetHTTPResultTrue();
end;

function TDemoController.OneGetName(Name: string): string;
begin
  Result := '上传的Url参数name=' + Name;
end;

function TDemoController.OneGetPerson(Name: string; age: integer): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.Name := Name;
  lPersonDemo.age := age;
  Result := lPersonDemo;
end;

// 以OnePost开头只支持post访问,参数name,age取自提交的JSON数据{name: "范联满1", age: 32}
function TDemoController.OnePostPerson(Name: string; age: integer): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin
  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.Name := Name;
  lPersonDemo.age := age;
  Result := lPersonDemo;
end;

// 以OnePost开头只支持post访问,参数直接取自提交的JSON数据{name: "范联满1", age: 32}反射成類 TPersonDemo
function TDemoController.OnePostPersonClass(person: TPersonDemo): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin

  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.Name := person.Name;
  lPersonDemo.age := person.age;
  // person，lPersonDemo 底程負責釋放,无需手动释放
  Result := lPersonDemo;
end;

// 混合参数
// 以OnePost开头只支持post访问,混合参数person,name取自提交的JSON数据{person:{name: "范联满1", age: 32},name:"范联满2"}反射成類 TPersonDemo
function TDemoController.OnePostPersonB(person: TPersonDemo; Name: string): TPersonDemo;
var
  lPersonDemo: TPersonDemo;
begin

  lPersonDemo := TPersonDemo.Create;
  lPersonDemo.Name := person.Name + '_' + Name;
  lPersonDemo.age := person.age;
  // person，lPersonDemo 底程負責釋放,无需手动释放
  Result := lPersonDemo;
end;

//特别注意需要先注册泛型 OneSerialization.AddListClass(TList<TPersonDemo>, TPersonDemo, nil);
function TDemoController.OnePostPersonList(persons: TList<TPersonDemo>): TList<
TPersonDemo>;
var
  lPersonDemo: TPersonDemo;
  i: integer;
begin
  Result := TList<TPersonDemo>.Create;
  for i := 0 to persons.Count - 1 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.Name := persons[i].Name;
    lPersonDemo.age := persons[i].age;
    Result.Add(lPersonDemo);
  end;
end;

function TDemoController.OneGetPersonResult(): TPersonResult;
begin
  Result := TPersonResult.Create;
  Result.resultCode := '123';
  Result.resultMsg := '哈哈哈';
  // 记得重写 TPersonResult 释放时要判断 person是不是为nil
  // 底程释圹只释圹 TPersonResult.free;
  Result.person.Name := 'flm';
  Result.person.age := 19;
end;

function TDemoController.OnePostPersonResult(personResult: TPersonResult): string;
begin
  Result := '收到数据成功 code->' + personResult.resultCode;
  if personResult.person <> nil then
  begin
    Result := Result + ';name->' + personResult.person.Name;
  end;
end;

function TDemoController.OneGetPersonListResult(): TPersonListResult;
var
  lPersonDemo: TPersonDemo;
  i: integer;
begin
  Result := TPersonListResult.Create;
  Result.resultCode := '123';
  Result.resultMsg := '哈哈哈';
  for i := 0 to 9 do
  begin
    lPersonDemo := TPersonDemo.Create;
    lPersonDemo.Name := 'flm';
    lPersonDemo.age := 18;
    Result.persons.Add(lPersonDemo);
  end;

end;

function TDemoController.OnePostPersonListResult(personListResult:
  TPersonListResult): string;
begin
  Result := '收到数据成功 code->' + personListResult.resultCode;
  if personListResult.persons <> nil then
  begin
    Result := Result + ';count->' + personListResult.persons.Count.ToString();
  end;
end;

function CreateNewDemoController(QRouterItem: TOneRouterItem): TObject;
var
  lController: TDemoController;
begin
  // 自定义创建控制器类，否则会按 TPersistentclass.create
  // 最好自定义一个好
  lController := TDemoController.Create;
  // 挂载RTTI信息
  lController.RouterItem := QRouterItem;
  Result := lController;
end;

procedure HelloWorldEven(QHTTPCtxt: THTTPCtxt; QHTTPResult: THTTPResult);
begin
  QHTTPResult.ResultOut := '欢迎来到HelloWorldEven';
end;

// 注册到路由
initialization

  // 注意，路由名称 不要一样，否则会判定已注册过，跳过
  // 多例模式注册
  OneHttpRouterManage.GetInitRouterManage().AddHTTPPoolWork('DemoA',
    TDemoController, TypeInfo(IDemoController), 100, CreateNewDemoController);
  // 单例模式注册
  OneHttpRouterManage.GetInitRouterManage().AddHTTPSingleWork('DemoB',
    TDemoController, TypeInfo(IDemoController), 100, CreateNewDemoController);
  // 方法注册
  //OneHttpRouterManage.GetInitRouterManage().AddHTTPEvenWork('DemoEven',
  //  HelloWorldEven, 10);
  //泛型注册
  OneSerialization.AddListClass(TList<TPersonDemo>, TPersonDemo, nil);

finalization

end.
