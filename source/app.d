import core.memory;
import core.sys.windows.windows;
import std.getopt;
import std.stdio;
import std.string;
import std.json;
import std.conv;
import std.utf;
import wind.string;

bool hexDisplay;
bool silentMode;
string[][] callbackReceives;

struct FunctionParameter
{
    string type;
    string value;
    string[] subtypes; // for struct members

    size_t rawParam; // the real param that pushed to call stack

    // since we cast c-style string pointers to uint for asm-level parameter passing,
    // there must be at least one reference to each temporary c-string to make sure they won't be freed.
    void*[] strref;

    // buffer to receive data as an output parameter
    void* buffer;
    size_t bufferlen;
};

__gshared FunctionParameter[] callbackParams;
__gshared uint callbackReturnValue;


void CallbackFunction()
{
    asm { naked; }

    version (X86)
    {
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
            call collectCallbackParameters;

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
}


void collectCallbackParameters()
{
    string[] values;
    foreach (param; callbackParams)
    {
        values ~= decodeRawData(param.type, param.rawParam, 0);
    }
    callbackReceives ~= values;
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

string decodeRawData(string basetype, size_t data, size_t len)
{
    switch (basetype)
    {
    case "str":
        return JSONValue(stringFromCStringA(cast(void*)data)).toString();
    case "wstr":
        return JSONValue(stringFromCStringW(cast(void*)data)).toString();
    case "plen":
    case "pint":
        return to!string(*cast(uint*)data);
    case "buffer":
        return hexDump(cast(void*)data, len);
    case "int":
    case "word":
        return (hexDisplay?"0x":"") ~ to!string(data, hexDisplay?16:10);
    default:
        return "";
    }
}

string decodeParam(FunctionParameter param)
{
    string basetype = getBasetype(param.type);
    if (basetype != "struct" && basetype != "pstruct")
        return decodeRawData(basetype, cast(uint)param.buffer, param.bufferlen);

    // struct
    string[] values;
    void* p = param.buffer;
    foreach (t; param.subtypes)
    {
        switch (t)
        {
        default:
            values ~= decodeRawData(t, cast(uint)p, 0);
            p += 4;
            break;
        case "word":
            uint tmp = *(cast(short*)p);
            values ~= decodeRawData(t, tmp, 0);
            p += 2;
        }
    }
    return values.join(",");
}
                             

/// Call an address with dynamic parameters which are stored in params
uint callFunction(const(void)* funcaddr, FunctionParameter[] params)
{
    uint retval = 0;

    version (X86)
    {
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
    }

    version (X86_64)
    {
        asm
        {
            push RCX;
            push RDX;
            push RDI;
            mov RDI, RSP;

            // RCX, RDX, R8, R9, ...

            mov RCX, qword ptr [params];

        CALL:
            call funcaddr;
            mov dword ptr [retval], EAX;
            
            mov RSP, RDI;
            pop RDI;
            pop RDX;
            pop RCX;
        }
    }
    
    return retval;
}

string generalHelp = `
parameter spec        description
==============        =========================================================
int:<number>          matches all 32 bit compitable integral types.
word:<number>         the same as "int", but only occupy 2 bytes inside struct.
len:<number>          used when previous param is a buffer. in such case it
                      specifies the buffer size.
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
out-pstruct:<{t,t,t}> output structure.
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
    auto helpInformation = getopt(
        args, 
        "hexdisp", "Hex display mode: display integers with hex", &hexDisplay,
        "silent|S", "silent mode: do not print anything", &silentMode
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
        case "word":
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
            param.bufferlen = fields.length * 4;
            param.buffer = GC.malloc(param.bufferlen);
            param.rawParam = cast(uint)param.buffer;
            void* p = param.buffer;
            foreach (field; fields)
            {
                string t = splitHead(field, ':');
                string v = splitTail(field, ':', "");
                param.subtypes ~= t;
                switch (t)
                {
                case "int":
                    *(cast(uint*)p) = toUint(v);
                    p += 4;
                    break;
                case "word":
                    *(cast(short*)p) = cast(short)(toUint(v));
                    p += 2;
                    break;
                case "str":
                    auto str = v.toStringz();
                    param.strref ~= cast(void*)str;
                    *(cast(uint*)p) = cast(uint)str;
                    p += 4;
                    break;
                case "wstr":
                    auto wstr = v.toUTF16z();
                    param.strref ~= cast(void*)wstr;
                    *(cast(uint*)p) = cast(uint)wstr;
                    p += 4;
                    break;
                default:
                    writeln("unknow struct member type.");
                    return;
                }
            }
            break;

        case "out-pstruct":
            param.subtypes = split(param.value, ",");
            param.bufferlen = param.subtypes.length * 4;
            param.buffer = GC.malloc(param.bufferlen);
            param.rawParam = cast(uint)param.buffer;
            break;
        }
    }

    size_t callbackCount = count!((a) => a.type == "callback")(params);
    if (callbackCount > 1)
    {
        writeln("at most one parameter can be 'callback'");
        return;
    }
                
    uint retval = callFunction(addr, params);

    if (silentMode)
    {
        return;
    }

    uint lastError = GetLastError();
    string retstr = decodeRawData(returnType, retval, 0);
    writeln("return value:", retstr);
    writeln("last error:", lastError);

    string outputParamValues;
    foreach (index, param; params)
    {
        if (!param.type.startsWith("out-") && !param.type.startsWith("inout-")) 
            continue;

        string value = decodeParam(param);
        outputParamValues ~= "  param" ~ to!string(index+1) ~ "=" ~ value ~ "\n";
    }
    if (outputParamValues.length)
    {
        writeln("output params:");
        writeln(outputParamValues);
    }

    if (callbackCount > 0)
    {
        writeln("callback receives:");
        foreach (values; callbackReceives)
        {
            writeln("    ", values.join(","));
        }
    }
}

