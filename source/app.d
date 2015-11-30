import core.memory;
import core.sys.windows.windows;
import std.getopt;
import std.stdio;
import std.string;
import std.conv;
import std.utf;
import wind.string;

struct FunctionParameter
{
    string type;
    string value;

    uint rawParam; // the real param that pushed to call stack

    // since we cast c-style string pointers to uint for asm-level parameter passing,
    // there must be at least one reference to each c-string to make sure they won't be freed.
    void*[] strref;

    // buffer to receive data as an output parameter
    void* buffer;
    uint bufferlen;
};

__gshared FunctionParameter[] callbackParams;
__gshared uint callbackReturnValue;

void CallbackFunction()
{
    asm { naked; }

    asm
    {
        push EBP;
        mov EBP, ESP;
        push ECX;
        push EDX;
        push ESI;
        push EDI;

        mov EDI, dword ptr[callbackParams];
        mov ESI, 0;

    CMP:
        cmp ESI, EDI;
        jge CALL;

        mov ECX, dword ptr [EBP + 8 + ESI*4];
        // the position of callbackParams[i].rawParam
        // := *(&callbackParams + 4) + FunctionParameter.sizeof * i + FunctionParameter.rawParam.offsetof
        mov EAX, FunctionParameter.sizeof;
        mul ESI;
        mov EDX, dword ptr [callbackParams + 4];
        mov dword ptr [EDX + EAX + FunctionParameter.rawParam.offsetof], ECX;

        inc ESI;
        jmp CMP;

    CALL:
        call DisplayCallbackParameters;

        // before we return we must clean up the passed parameters because Windows expect the callback to clear the 
        // parameter. 
        // typically the callee uses 'RET n' to achieve this. however we cannot use it because the parameter count
        // cannot be determined at compile time.
        // below is our algorithm:
        // [original EBP value] [return address] [param 1] [param 2] ... [param n]
        // ^(EBP points here)
        // 1. copy return-address to the first pushed param (param n) position on the stack
        // 2. restore registers and epilog as usual
        // 3. move esp to the first pushed param position on the stack, which is the caller expected after 'RET'
        // 4. set return value and RET

        lea EAX, dword ptr [EBP + 4 + ESI*4];
        mov ECX, dword ptr [EBP + 4];
        mov dword ptr [EAX], ECX;

        pop EDI;
        pop ESI;
        pop EDX;
        pop ECX;
        mov ESP, EBP;
        pop EBP;

        mov ESP, EAX;
        mov EAX, dword ptr [callbackReturnValue];
        ret;
    }
}

void DisplayCallbackParameters()
{
    string str = "  ";
    foreach (param; callbackParams)
    {
        str ~= decodeRawData(param.type, param.rawParam, 0);
        str ~= " ";
    }
    writeln(str);
}

uint toUint(string str)
{
    if (str.length == 0)
        return 0;

    if (str.startsWith("0x") || str.startsWith("0X"))
        return to!uint(str[2..$], 16);

    return to!uint(str);
}

string getBasetype(string type)
{
    return splitTail(type, '-', type);
}

string decodeRawData(string basetype, uint data, uint len)
{
    switch (basetype)
    {
    case "str":
        return stringFromCStringA(cast(void*)data);
    case "wstr":
        return stringFromCStringW(cast(void*)data);
    case "plen":
    case "pint":
        return to!string(*cast(uint*)data);
    case "buffer":
        return hexDump(cast(void*)data, len);
    case "int":
        return to!string(data);
    default:
        return "";
    }
}

/// Call an address with dynamic parameters which are stored in params
uint callFunction(const(void)* funcaddr, FunctionParameter[] params)
{
    uint retval = 0;
    asm
    {
        push ECX;
        push EDX;
        
        mov ECX, dword ptr [params];
        CMP:
        cmp ECX, 0;
        je CALL;
        sub ECX, 1;

        // the position of params[i].rawParam
        // := *(&params + 4) + FunctionParameter.sizeof * i + FunctionParameter.rawParam.offsetof
        mov EAX, FunctionParameter.sizeof;
        mul ECX;
        mov EDX, dword ptr [params + 4];
        push dword ptr [EDX + EAX + FunctionParameter.rawParam.offsetof];
        jmp CMP;
        CALL:
        call funcaddr;
        mov dword ptr [retval], EAX;

        pop EDX;
        pop ECX;
    }
    return retval;
}

string generalHelp = `
parameter spec        description
==============        =========================================================
int:<number>          integer. matches DWORD, UINT, and other compitable types
len:<number>          integer, also specifies the length of the previous param
str:<string>          ANSI string. maches LPCSTR
wstr:<string>         UNICODE string. matches LPCWSTR
out-pint              output integer. matches LPDWORD, ...
inout-plen:<number>   output integer, also specifies the length of the previous
                      param, and also receives a value related to that param
out-str:<number>      output ANSI string. matches LPSTR
out-wstr:<number>     output UNICODE string. matches LPWSTR
out-buffer:<number>   output buffer. matches all output pointers that have
                      array semantics. 
struct:<{t:v,t:v...}> structure.
callback:<t,t,t:ret>  callback function.

<number> can be any decimal or hex values. e.g. 10, 256, 0x80, 0xFFFF
<string> must be quoted with " if it contains spaces. e.g.: "English Locale"
{t:v,t:v...} defines a struct. "t" can be all input types listed above.
t,t,t:ret defines a callback function. "t" can be all input types listed above.

calldll calls the specified export function in DLL, using the given parameters.
After the call, it will print the following to standard output:
1. the values that the callback function receives (if callback exists)
2. the function return value
3. all output parameter values

examples:

calldll user32.dll SendNotifyMessageW int:0xffff int:0x1A int:0 wstr:Environment
notify explorer to refresh environment variables after you manually change them.

calldll user32.dll AllowSetForegroundWindow int:0xffffffff
use it before you want to bring another window to foreground.

calldll kernel32.dll Sleep int:5000 >nul
this implements a sleep in command line.

calldll shell32.dll ShellExecuteA int:0 str:runas str:cmd.exe int:0 int:0 int:5
this opens an elevated command line.

calldll user32.dll EnumWindows callback:int,int:0 int:0x100
`;

void main(string[] args)
{
    bool hexDisplay;
    auto helpInformation = getopt(
        args, 
        "hexdisp", "Hex display mode: display integers with hex", &hexDisplay
        );
    if (helpInformation.helpWanted || args.length < 3)
    {
        defaultGetoptPrinter("usage: calldll [options] dllname function parameter1 parameter2 ...", helpInformation.options);
        write(generalHelp);
        return;
    }

    string dllname = args[1];
    string funcname = splitHead(args[2], ':');
    string returnType = splitTail(args[2], ':', "int");
    HMODULE mod = LoadLibraryW(std.utf.toUTF16z(dllname));
    if (!mod)
    {
        writeln("load library failed");
        return;
    }

    FARPROC addr = GetProcAddress(mod, funcname.toStringz());
    if (!addr)
    {
        writeln("Function not found");
        return;
    }

    FunctionParameter[] params;
    foreach (i, string arg; args[3..$])
    {
        FunctionParameter p;
        p.type = splitHead(arg, ':');
        p.value = splitTail(arg, ':', "");
        params ~= p;
    }

    bool hasCallback = false;
    foreach(i, ref param; params)
    {
        switch (param.type)
        {
        default:
            writeln("unknown param type:", param.type);
            return;
            
        case "len":
        case "int":
            param.rawParam = toUint(param.value);
            break;
        
        case "str":
            auto str = param.value.toStringz();
            param.strref ~= cast(void*)str;
            param.rawParam = cast(uint)(str);
            break;
            
        case "wstr": 
            auto wstr = param.value.toUTF16z();
            param.strref ~= cast(void*)wstr;
            param.rawParam = cast(uint)(wstr);
            break;
            
        case "out-str":
        case "out-wstr":
        case "out-buffer":
            uint len = toUint(param.value);
            if (len == 0)
            {
                // see if the next param is "len", if so, use the length instead of param.value
                if (i+1 < params.length)
                {
                    auto nextParam = params[i+1];
                    if (nextParam.type == "len" || nextParam.type == "inout-plen")
                    {
                        len = toUint(nextParam.value) * 4;
                    }
                }
            }
            if (len == 0)
            {
                writeln("param #%s is output string, but there is no length of it".format(i));
                return;
            }
            param.bufferlen = len; // we waste buffer here if the param type is not wstr
            param.buffer = GC.malloc(len);
            param.rawParam = cast(uint)(param.buffer);
            break;
            
        case "inout-plen":
        case "out-pint":
            param.buffer = GC.malloc(4);
            uint* p = cast(uint*)(param.buffer);
            *p = toUint(param.value);
            param.rawParam = cast(uint)(p);
            break;
            
        case "callback":
            string paramspec = splitHead(param.value, ':');
            string returnspec = splitTail(param.value, ':', "1");
            callbackReturnValue = toUint(returnspec);
            foreach (type; split(paramspec, ","))
            {
                FunctionParameter p;
                p.type = type;
                callbackParams ~= p;
            }
            param.rawParam = cast(uint)(&CallbackFunction);
            break;
            
        case "struct":
            string[] fields = split(param.value, ",");
            uint* buffer = cast(uint*)GC.malloc(fields.length * 4);
            foreach (j, field; fields)
            {
                string k = splitHead(field, ':');
                string v = splitTail(field, ':', "");
                if (k == "int")
                {
                    buffer[j] = toUint(v);
                }
                else if (k == "str")
                {
                    auto str = v.toStringz();
                    param.strref ~= cast(void*)str;
                    buffer[j] = cast(uint)str;
                }
                else if (k == "wstr")
                {
                    auto wstr = v.toUTF16z();
                    param.strref ~= cast(void*)wstr;
                    buffer[j] = cast(uint)wstr;
                }
            }
            param.rawParam = cast(uint)buffer;
            break;
        }
    }
    
    switch (count!((a) => a.type == "callback")(params))
    {
    case 0:
        break;
    case 1:
        writeln("callback receives:");
        break;
    default:
        writeln("at most one parameter can be 'callback'");
        return;
    }
                
    uint retval = callFunction(addr, params);

    string retstr = decodeRawData(returnType, retval, 0);
    writeln("return value:", retstr);

    string outputParamValues;
    foreach (index, param; params)
    {
        if (!param.type.startsWith("out-") && !param.type.startsWith("inout-")) 
            continue;

        string value = decodeRawData(getBasetype(param.type), cast(uint)param.buffer, param.bufferlen);
        outputParamValues ~= "  param" ~ to!string(index+1) ~ "=" ~ value ~ "\n";
    }
    if (outputParamValues.length)
    {
        writeln("output params:");
        writeln(outputParamValues);
    }
}
