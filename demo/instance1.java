package com.testmyaes.opensslaes;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.testmyaes.findaes.AesKeyFinder;

import java.io.File;
import java.util.List;

import static com.testmyaes.findaes.AesKeyFinder.readFuncFromIDA;


public class instance1 {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    instance1() {

        emulator = AndroidEmulatorBuilder.for32Bit().build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        // 模拟器的内存操作接口
        final Memory memory = emulator.getMemory();
        // 设置系统类库解析
        memory.setLibraryResolver(new AndroidResolver(23));
        // 创建Android虚拟机
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/opensslLOW/myopensslaes.apk"));

        // 设置是否打印Jni调用细节
        vm.setVerbose(true);

        // 加载so到虚拟内存，加载成功以后会默认调用init_array等函数
        DalvikModule dm = vm.loadLibrary("opensslaes", true);
        // 加载好的 libscmain.so对应为一个模块
        module = dm.getModule();

        List<String> funclist = readFuncFromIDA("unidbg-android/src/test/resources/opensslLOW/libopensslaes_functionlist_1634138228.txt");
        AesKeyFinder aesKeyFinder = new AesKeyFinder(emulator);
        aesKeyFinder.searchEveryFunction(module.base, funclist);

        dm.callJNI_OnLoad(emulator);
    }

    public void call(){
        DvmClass dvmClass = vm.resolveClass("com/example/opensslaes/MainActivity");
        String methodSign = "stringFromJNI()Ljava/lang/String;";
        DvmObject<?> dvmObject = dvmClass.newObject(null);

        StringObject obj = dvmObject.callJniMethodObject(emulator, methodSign);
        System.out.println(obj.getValue());
    }

    public static void main(String[] args) {
        instance1 demo = new instance1();
        demo.call();
    }
}
