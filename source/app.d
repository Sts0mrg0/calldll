import core.memory;
import core.sys.windows.windows;
import std.getopt;
import std.stdio;
import std.string;
import std.json;
import std.conv;
import std.utf;
import std.variant;
import wind.string;
import std.exception : enforce;

Variant[][] callbackArgs;
FunctionParameter[] callbackParams;
uint callbackReturnValue;

struct FunctionParameter
{
    string type;
    string value;
    string[] subtypes; // for struct members

    size_t rawParam; // the real param that pushed to call stack

    // since we cast c-style string pointers to integer for asm-level parameter passing,
    // there must be at least one reference to each temporary c-string to make sure they won't be freed.
    void*[] strref;

    // buffer to receive data as an output parameter
    void* buffer;
    size_t bufferlen;
};

size_t toUint(string str)
{
    if (str.length == 0)
        return 0;

    if (str.startsWith("0x") || str.startsWith("0X"))
        return to!size_t(str[2..$], 16);

    return to!size_t(str);
}

uint toUint32(string str) {
    return cast(uint)toUint(str);
}

string getBasetype(string type)
{
    return splitTail(type, '-', type);
}

Variant rawDataToVariant(string basetype, size_t data, size_t len)
{
    Variant v;
    switch (basetype)
    {
        case "str":
            v = stringFromCStringA(cast(void*)data); break;
        case "wstr":
            v = stringFromCStringW(cast(void*)data); break;
        case "plen":
        case "pint":
            v = *cast(uint*)data; break;
        case "buffer":
            v = (cast(byte*)data)[0..len];
            break;
        case "int":
        case "word":
            v = cast(uint)data;
            break;
        default:
            break;
    }

    return v;
}

Variant paramToVariant(FunctionParameter param)
{
    string basetype = getBasetype(param.type);
    if (basetype != "struct" && basetype != "pstruct")
        return rawDataToVariant(basetype, cast(size_t)param.buffer, param.bufferlen);

    // struct
    Variant[] val;
    void* p = param.buffer;
    foreach (t; param.subtypes)
    {
        switch (t)
        {
            default:
                val ~= rawDataToVariant(t, cast(size_t)p, 0);
                p += size_t.sizeof;
                break;
            case "word":
                uint tmp = *(cast(short*)p);
                val ~= rawDataToVariant(t, tmp, 0);
                p += short.sizeof;
        }
    }
    Variant ret = val;
    return ret;
}

size_t processCallback(size_t[] args)
{
    Variant[] arg;
    foreach (i, param; callbackParams)
    {
        arg ~= rawDataToVariant(param.type, args[i], 0);
    }
    callbackArgs ~= arg;
    return callbackReturnValue;
}

extern(Windows)
{
    alias size_t function() winapi_0;
    alias size_t function(size_t) winapi_1;
    alias size_t function(size_t, size_t) winapi_2;
    alias size_t function(size_t, size_t, size_t) winapi_3;
    alias size_t function(size_t, size_t, size_t, size_t) winapi_4;
    alias size_t function(size_t, size_t, size_t, size_t, size_t) winapi_5;
    alias size_t function(size_t, size_t, size_t, size_t, size_t, size_t) winapi_6;
    alias size_t function(size_t, size_t, size_t, size_t, size_t, size_t, size_t) winapi_7;
    alias size_t function(size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t) winapi_8;
    alias size_t function(size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t) winapi_9;

    size_t callback_thunk_0() { return processCallback([]); }
    size_t callback_thunk_1(size_t a1                                                                                            ) {return processCallback([a1]); }
    size_t callback_thunk_2(size_t a1, size_t a2                                                                                 ) {return processCallback([a1, a2]); }
    size_t callback_thunk_3(size_t a1, size_t a2, size_t a3                                                                      ) {return processCallback([a1, a2, a3]); }
    size_t callback_thunk_4(size_t a1, size_t a2, size_t a3, size_t a4                                                           ) {return processCallback([a1, a2, a3, a4]); }
    size_t callback_thunk_5(size_t a1, size_t a2, size_t a3, size_t a4, size_t a5                                                ) {return processCallback([a1, a2, a3, a4, a5]); }
    size_t callback_thunk_6(size_t a1, size_t a2, size_t a3, size_t a4, size_t a5, size_t a6                                     ) {return processCallback([a1, a2, a3, a4, a5, a6]); }
    size_t callback_thunk_7(size_t a1, size_t a2, size_t a3, size_t a4, size_t a5, size_t a6, size_t a7                          ) {return processCallback([a1, a2, a3, a4, a5, a6, a7]); }
    size_t callback_thunk_8(size_t a1, size_t a2, size_t a3, size_t a4, size_t a5, size_t a6, size_t a7, size_t a8               ) {return processCallback([a1, a2, a3, a4, a5, a6, a7, a8]); }
    size_t callback_thunk_9(size_t a1, size_t a2, size_t a3, size_t a4, size_t a5, size_t a6, size_t a7, size_t a8, size_t a9    ) {return processCallback([a1, a2, a3, a4, a5, a6, a7, a8, a9]); }
}

size_t[] getCallbackAddresses()
{
    return
    [
        cast(size_t)(&callback_thunk_0),
        cast(size_t)(&callback_thunk_1),
        cast(size_t)(&callback_thunk_2),
        cast(size_t)(&callback_thunk_3),
        cast(size_t)(&callback_thunk_4),
        cast(size_t)(&callback_thunk_5),
        cast(size_t)(&callback_thunk_6),
        cast(size_t)(&callback_thunk_7),
        cast(size_t)(&callback_thunk_8),
        cast(size_t)(&callback_thunk_9),
    ];
}

size_t callFunctionNew(const(void)* funcaddr, size_t[] p)
{
    size_t ret = 0;
    switch (p.length)
    {
    case 0: ret = (cast(winapi_0)funcaddr)(); break;
    case 1: ret = (cast(winapi_1)funcaddr)(p[0]); break;
    case 2: ret = (cast(winapi_2)funcaddr)(p[0], p[1]); break;
    case 3: ret = (cast(winapi_3)funcaddr)(p[0], p[1], p[2]); break;
    case 4: ret = (cast(winapi_4)funcaddr)(p[0], p[1], p[2], p[3]); break;
    case 5: ret = (cast(winapi_5)funcaddr)(p[0], p[1], p[2], p[3], p[4]); break;
    case 6: ret = (cast(winapi_6)funcaddr)(p[0], p[1], p[2], p[3], p[4], p[5]); break;
    case 7: ret = (cast(winapi_7)funcaddr)(p[0], p[1], p[2], p[3], p[4], p[5], p[6]); break;
    case 8: ret = (cast(winapi_8)funcaddr)(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]); break;
    case 9: ret = (cast(winapi_9)funcaddr)(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]); break;
    default: break;
    }

    return ret;
}

struct CallResult
{
    uint lastError;
    Variant returnValue;
    Variant[] outputParameters;
    Variant[][] callbackArgs;
}

CallResult makeCall(string dllFileName, string functionSpec, string[] parameterSpecs)
{
    CallResult ret;
    string funcname = splitHead(functionSpec, ':');
    string returnType = splitTail(functionSpec, ':', "int");
    HMODULE mod = LoadLibraryW(std.utf.toUTF16z(dllFileName));
    enforce(mod, "load library failed");

    FARPROC addr = GetProcAddress(mod, funcname.toStringz());
    enforce(addr, "Function not found");

    FunctionParameter[] params;
    foreach (i, string arg; parameterSpecs)
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
                enforce(false, "unknown param type:");
                break;

            case "len":
            case "int":
            case "word":
                param.rawParam = toUint(param.value);
                break;

            case "str":
                auto str = param.value.toStringz();
                param.strref ~= cast(void*)str;
                param.rawParam = cast(size_t)(str);
                break;

            case "wstr": 
                auto wstr = param.value.toUTF16z();
                param.strref ~= cast(void*)wstr;
                param.rawParam = cast(size_t)(wstr);
                break;

            case "out-str":
            case "out-wstr":
            case "out-buffer":
                size_t len = toUint(param.value);
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

                enforce(len > 0, "param #%s is output string, but there is no length of it".format(i));

                param.bufferlen = len; // we waste buffer here if the param type is not wstr
                param.buffer = GC.malloc(len);
                param.rawParam = cast(size_t)(param.buffer);
                break;

            case "inout-plen":
            case "out-pint":
                param.buffer = GC.malloc(4);
                uint* p = cast(uint*)(param.buffer);
                *p = toUint32(param.value);
                param.rawParam = cast(size_t)(p);
                break;

            case "callback":
                string paramspec = splitHead(param.value, ':');
                string returnspec = splitTail(param.value, ':', "1");
                callbackReturnValue = toUint32(returnspec);
                foreach (type; split(paramspec, ","))
                {
                    FunctionParameter p;
                    p.type = type;
                    callbackParams ~= p;
                }
                param.rawParam = getCallbackAddresses()[callbackParams.length];
                break;

            case "struct":
                string[] fields = split(param.value, ",");
                param.bufferlen = fields.length * 4;
                param.buffer = GC.malloc(param.bufferlen);
                param.rawParam = cast(size_t)param.buffer;
                void* p = param.buffer;
                foreach (field; fields)
                {
                    string t = splitHead(field, ':');
                    string v = splitTail(field, ':', "");
                    param.subtypes ~= t;
                    switch (t)
                    {
                        case "int":
                            *(cast(uint*)p) = toUint32(v);
                            p += 4;
                            break;
                        case "word":
                            *(cast(short*)p) = cast(short)(toUint(v));
                            p += 2;
                            break;
                        case "str":
                            auto str = v.toStringz();
                            param.strref ~= cast(void*)str;
                            *(cast(size_t*)p) = cast(size_t)str;
                            p += size_t.sizeof;
                            break;
                        case "wstr":
                            auto wstr = v.toUTF16z();
                            param.strref ~= cast(void*)wstr;
                            *(cast(size_t*)p) = cast(size_t)wstr;
                            p += size_t.sizeof;
                            break;
                        default:
                            enforce(false, "unknow struct member type.");
                    }
                }
                break;

            case "out-pstruct":
                param.subtypes = split(param.value, ",");
                param.bufferlen = param.subtypes.length * 4;
                param.buffer = GC.malloc(param.bufferlen);
                param.rawParam = cast(size_t)param.buffer;
                break;
        }
    }

    size_t callbackCount = count!((a) => a.type == "callback")(params);
    enforce(callbackCount <= 1, "at most one parameter can be 'callback'");

    size_t[] rawparams;
    foreach (index, param; params)
    {
        rawparams ~= param.rawParam;
    }

    size_t retval = callFunctionNew(addr, rawparams);

    ret.lastError = GetLastError();
    ret.returnValue = rawDataToVariant(returnType, retval, 0);

    string outputParamValues;
    foreach (index, param; params)
    {
        if (!param.type.startsWith("out-") && !param.type.startsWith("inout-")) 
            continue;

        ret.outputParameters ~= paramToVariant(param);
    }

    ret.callbackArgs = callbackArgs;

    callbackArgs.length = 0;
    callbackParams.length = 0;

    return ret;
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
    bool hexDisplay;
    bool silentMode;
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

    CallResult ret = makeCall(args[1], args[2], args[3..$]);
    writeln("return value:", ret.returnValue);
    writeln("last error:", ret.lastError);
    writeln("output parameters:", ret.outputParameters);
    writeln("callback args:", ret.callbackArgs);
}

