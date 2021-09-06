hook 获取到寄存器的值


import frida, sys

jscode = """
var str_name_so = "libSTD.so";    //要hook的so名
var str_name_so2 = "libDEVICEID.so";    //要hook的so名
var str_name_so3 = "libCOMM_ABSTRACT_LAYER.so";    //要hook的so名
var str_name_so4 = "libGM_DTCF.so";    //要hook的so名
var str_name_so5 = "libTOYOTA_CDSF.so";    //要hook的so名


var str_name_func = "ShowMessageBoxID";          //要hook的函数名ShowMessageBox
var str_name_func2 = "ShowMessageBox";          //要hook的函数名
var str_name_func3 = "fopenEx";          //要hook的函数名
var str_name_func4 = "SetEnterFrame";          //要hook的函数名
var str_name_func5 = "SendDataToSmartBoxGetBinaryString";          //要hook的函数名
var str_name_func6 = "InitMenuID";          //要hook的函数名
var str_name_func7 = "AddMenuTextID";          //要hook的函数名
var str_name_func8 = "CanSetParameterALL";          //要hook的函数名
var str_name_func9 = "GetDtcCode";          //要hook的函数名
var str_name_func10 = "PidCheckSupportP4";          //要hook的函数名
var str_name_func11 = "HideDataMonitor";          //要hook的函数名
var str_name_func12 = "ReadDStreamFunc";          //要hook的函数名





//var str_name_func = "_Z12func_exp_cppv";    //这里注意名称粉碎

var n_addr_func = Module.findExportByName(str_name_so , str_name_func);
var n_addr_func2 = Module.findExportByName(str_name_so , str_name_func2);
var n_addr_func3 = Module.findExportByName(str_name_so2 , str_name_func3);
var n_addr_func4 = Module.findExportByName(str_name_so3 , str_name_func4);
var n_addr_func5 = Module.findExportByName(str_name_so , str_name_func5);
var n_addr_func6 = Module.findExportByName(str_name_so , str_name_func6);
var n_addr_func7 = Module.findExportByName(str_name_so , str_name_func7);
var n_addr_func8 = Module.findExportByName(str_name_so3 , str_name_func8);
var n_addr_func9 = Module.findExportByName(str_name_so4 , str_name_func9);
var n_addr_func10 = Module.findExportByName(str_name_so5 , str_name_func10);
var n_addr_func11 = Module.findExportByName(str_name_so5 , str_name_func11);
var n_addr_func12 = Module.findExportByName(str_name_so5 , str_name_func12);




console.log("func ShowMessageBoxID addr is ---" + n_addr_func);
console.log("func ShowMessageBox addr is ---" + n_addr_func2);
console.log("func fopenEx addr is ---" + n_addr_func3);
console.log("func SetEnterFrame addr is ---" + n_addr_func4);
console.log("func SendDataToSmartBoxGetBinaryString addr is ---" + n_addr_func5);
console.log("func InitMenuID addr is ---" + n_addr_func6);
console.log("func AddMenuTextID addr is ---" + n_addr_func7);
console.log("func CanSetParameterALL addr is ---" + n_addr_func8);
console.log("func GetDtcCode addr is ---" + n_addr_func9);
console.log("func PidCheckSupportP4 addr is ---" + n_addr_func10);
console.log("func HideDataMonitor addr is ---" + n_addr_func11);
console.log("func ReadDStreamFunc addr is ---" + n_addr_func12);





Interceptor.attach(n_addr_func12, {
    //在hook函数之前执行的语句

    
    onEnter: function(args)
    {
        //console.log("SendDataToSmartBoxGetBinaryString hook on enter")
       //console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        //console.log('RegisterNatives called from:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n');

        //var buf = Memory.readByteArray(args[0],128);
        //console.log(hexdump(buf, { offset: 0,length: 128,header: false,ansi: false}));
        //console.log("\\n");
        this.val = args[1];
        
        
        var base_CDSF_jni = Module.findBaseAddress(str_name_so5);
        console.log("base_CDSF_jni:", base_CDSF_jni);
        if (base_CDSF_jni) {
            //inline hook
            var addr_Addxx = base_CDSF_jni.add(0xA784);//指令执行的地址，不是变量所在的栈或堆
            console.log(addr_Addxx);
            
            
            console.log("inline hook start");
            var readAddr = this.context.r1 + 0x448;//注意这里是怎么得到寄存器值的  // 打印寄存器w13 w14（ARM64下为x13 x14）
            console.log("addr_Addxx r1+0x448:", readAddr);
            console.log("\\n");
            console.log(hexdump(ptr(readAddr), { offset: 0,length: 1,header: false,ansi: false}));
            //console.log("addr_Addxx x13+0x80E Val:", ptr(readAddr).readCString());
                
        }
        
    },
    //在hook函数之后执行的语句
    onLeave:function(retval)
    { 
        var buf = Memory.readByteArray(this.val,1);
        //console.log(hexdump(buf, { offset: 0,length: 1,header: false,ansi: false}));
       //var valRet = this.val[0]; 
        //console.log(retval );     
        //console.log("hook on leave")
    }
});



//获取到so某一处地址的寄存器的值








"""

def message(message, data):
    if message["type"] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

process = frida.get_remote_device().attach('com.cnlaunch.diagnoseservice')
script= process.create_script(jscode)
script.on("message", message)
script.load()
sys.stdin.read()

