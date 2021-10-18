package com.testmyaes.findaes;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;

public class AesKeyFinder {

    protected final Emulator<?> emulator;
    protected Backend backend;
    protected List<byte[]> keylist = new ArrayList<>();
    protected List<Long> breakTrace = new ArrayList<>();
    protected byte[] MemoryRegion;


    private static final byte[] Sbox = {
            (byte)0x63,(byte)0x7c,(byte)0x77,(byte)0x7b,(byte)0xf2,(byte)0x6b,(byte)0x6f,(byte)0xc5,
            (byte)0x30,(byte)0x01,(byte)0x67,(byte)0x2b,(byte)0xfe,(byte)0xd7,(byte)0xab,(byte)0x76,
            (byte)0xca,(byte)0x82,(byte)0xc9,(byte)0x7d,(byte)0xfa,(byte)0x59,(byte)0x47,(byte)0xf0,
            (byte)0xad,(byte)0xd4,(byte)0xa2,(byte)0xaf,(byte)0x9c,(byte)0xa4,(byte)0x72,(byte)0xc0,
            (byte)0xb7,(byte)0xfd,(byte)0x93,(byte)0x26,(byte)0x36,(byte)0x3f,(byte)0xf7,(byte)0xcc,
            (byte)0x34,(byte)0xa5,(byte)0xe5,(byte)0xf1,(byte)0x71,(byte)0xd8,(byte)0x31,(byte)0x15,
            (byte)0x04,(byte)0xc7,(byte)0x23,(byte)0xc3,(byte)0x18,(byte)0x96,(byte)0x05,(byte)0x9a,
            (byte)0x07,(byte)0x12,(byte)0x80,(byte)0xe2,(byte)0xeb,(byte)0x27,(byte)0xb2,(byte)0x75,
            (byte)0x09,(byte)0x83,(byte)0x2c,(byte)0x1a,(byte)0x1b,(byte)0x6e,(byte)0x5a,(byte)0xa0,
            (byte)0x52,(byte)0x3b,(byte)0xd6,(byte)0xb3,(byte)0x29,(byte)0xe3,(byte)0x2f,(byte)0x84,
            (byte)0x53,(byte)0xd1,(byte)0x00,(byte)0xed,(byte)0x20,(byte)0xfc,(byte)0xb1,(byte)0x5b,
            (byte)0x6a,(byte)0xcb,(byte)0xbe,(byte)0x39,(byte)0x4a,(byte)0x4c,(byte)0x58,(byte)0xcf,
            (byte)0xd0,(byte)0xef,(byte)0xaa,(byte)0xfb,(byte)0x43,(byte)0x4d,(byte)0x33,(byte)0x85,
            (byte)0x45,(byte)0xf9,(byte)0x02,(byte)0x7f,(byte)0x50,(byte)0x3c,(byte)0x9f,(byte)0xa8,
            (byte)0x51,(byte)0xa3,(byte)0x40,(byte)0x8f,(byte)0x92,(byte)0x9d,(byte)0x38,(byte)0xf5,
            (byte)0xbc,(byte)0xb6,(byte)0xda,(byte)0x21,(byte)0x10,(byte)0xff,(byte)0xf3,(byte)0xd2,
            (byte)0xcd,(byte)0x0c,(byte)0x13,(byte)0xec,(byte)0x5f,(byte)0x97,(byte)0x44,(byte)0x17,
            (byte)0xc4,(byte)0xa7,(byte)0x7e,(byte)0x3d,(byte)0x64,(byte)0x5d,(byte)0x19,(byte)0x73,
            (byte)0x60,(byte)0x81,(byte)0x4f,(byte)0xdc,(byte)0x22,(byte)0x2a,(byte)0x90,(byte)0x88,
            (byte)0x46,(byte)0xee,(byte)0xb8,(byte)0x14,(byte)0xde,(byte)0x5e,(byte)0x0b,(byte)0xdb,
            (byte)0xe0,(byte)0x32,(byte)0x3a,(byte)0x0a,(byte)0x49,(byte)0x06,(byte)0x24,(byte)0x5c,
            (byte)0xc2,(byte)0xd3,(byte)0xac,(byte)0x62,(byte)0x91,(byte)0x95,(byte)0xe4,(byte)0x79,
            (byte)0xe7,(byte)0xc8,(byte)0x37,(byte)0x6d,(byte)0x8d,(byte)0xd5,(byte)0x4e,(byte)0xa9,
            (byte)0x6c,(byte)0x56,(byte)0xf4,(byte)0xea,(byte)0x65,(byte)0x7a,(byte)0xae,(byte)0x08,
            (byte)0xba,(byte)0x78,(byte)0x25,(byte)0x2e,(byte)0x1c,(byte)0xa6,(byte)0xb4,(byte)0xc6,
            (byte)0xe8,(byte)0xdd,(byte)0x74,(byte)0x1f,(byte)0x4b,(byte)0xbd,(byte)0x8b,(byte)0x8a,
            (byte)0x70,(byte)0x3e,(byte)0xb5,(byte)0x66,(byte)0x48,(byte)0x03,(byte)0xf6,(byte)0x0e,
            (byte)0x61,(byte)0x35,(byte)0x57,(byte)0xb9,(byte)0x86,(byte)0xc1,(byte)0x1d,(byte)0x9e,
            (byte)0xe1,(byte)0xf8,(byte)0x98,(byte)0x11,(byte)0x69,(byte)0xd9,(byte)0x8e,(byte)0x94,
            (byte)0x9b,(byte)0x1e,(byte)0x87,(byte)0xe9,(byte)0xce,(byte)0x55,(byte)0x28,(byte)0xdf,
            (byte)0x8c,(byte)0xa1,(byte)0x89,(byte)0x0d,(byte)0xbf,(byte)0xe6,(byte)0x42,(byte)0x68,
            (byte)0x41,(byte)0x99,(byte)0x2d,(byte)0x0f,(byte)0xb0,(byte)0x54,(byte)0xbb,(byte)0x16
    };

    private static final byte[] Rcon = {(byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08,
            (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36};

    public AesKeyFinder(Emulator<?> emulator) {
        this.emulator = emulator;
        this.backend = emulator.getBackend();

    }

    public byte getSBoxValue(byte num){
        return Sbox[byte2Int(num)];
    }


    private int byte2Int(byte b) {
        return (b & 0xff);
    }

    public int arrayEquals(byte[] arr1, byte[] arr2){
        if (Arrays.equals(arr1, arr2)) {
            return 1;
        }else {
            return 0;
        }
    };


    // 检索当前时机的内存中是否存在Key
    public boolean searchKeyInMemory() {
        int exist = 0;
        // 检索非模块的内存区域
        for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if(emulator.getMemory().findModuleByAddress(map.base) == null){
                exist += searchMemory(map.base, map.base + map.size);
            }
        }
        // 搜索当前栈
        UnidbgPointer stack = emulator.getContext().getStackPointer();
        long stackstart = stack.toUIntPeer();
        long stackend = emulator.getMemory().getStackBase();
        exist += searchMemory(stackstart, stackend);
        return exist > 0;
    }


    public boolean containsSubArray(List<byte[]> j, byte[] sub) {
        for (byte[] arr : j ) {
            if (Arrays.equals(arr, sub)) {
                return true;
            }
        }
        return false;
    }

    public byte[] ExpandKey128BigEdian(byte[] Key){
        byte[] RoundKey = new byte[176];
        int i, j, k;
        byte[] tempa = new byte[4];
        // The first round key is the key itself.
        for (i = 0; i < 4; ++i)
        {
            RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
            RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
            RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
            RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
        }
        for (i = 4; i < 4 * (10 + 1); ++i) {
            {
                k = (i - 1) * 4;
                tempa[0] = RoundKey[k + 0];
                tempa[1] = RoundKey[k + 1];
                tempa[2] = RoundKey[k + 2];
                tempa[3] = RoundKey[k + 3];
            }
            if(i % 4 == 0){
                {
                    // 循环左移
                    byte u8tmp = tempa[0];
                    tempa[0] = tempa[1];
                    tempa[1] = tempa[2];
                    tempa[2] = tempa[3];
                    tempa[3] = u8tmp;
                }

                // SubWord() is a function that takes a four-byte input word and
                // applies the S-box to each of the four bytes to produce an output word.

                // Function Subword()
                {
                    tempa[0] = getSBoxValue(tempa[0]);
                    tempa[1] = getSBoxValue(tempa[1]);
                    tempa[2] = getSBoxValue(tempa[2]);
                    tempa[3] = getSBoxValue(tempa[3]);
                }

                tempa[0] = (byte) (tempa[0] ^ Rcon[i/4]);

            }
            // 最后一步
            j = i * 4; k=(i - 4) * 4;
            RoundKey[j + 0] = (byte) (RoundKey[k + 0] ^ tempa[0]);
            RoundKey[j + 1] = (byte) (RoundKey[k + 1] ^ tempa[1]);
            RoundKey[j + 2] = (byte) (RoundKey[k + 2] ^ tempa[2]);
            RoundKey[j + 3] = (byte) (RoundKey[k + 3] ^ tempa[3]);
        }

        return RoundKey;
    };


    public byte[] ExpandKey256BigEdian(byte[] Key){
        byte[] RoundKey = new byte[240];
        int i, j, k;
        byte[] tempa = new byte[4];
        // The first round key is the key itself.
        for (i = 0; i < 8; ++i)
        {
            RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
            RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
            RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
            RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
        }
        for (i = 8; i < 4 * (14 + 1); ++i) {
            {
                k = (i - 1) * 4;
                tempa[0] = RoundKey[k + 0];
                tempa[1] = RoundKey[k + 1];
                tempa[2] = RoundKey[k + 2];
                tempa[3] = RoundKey[k + 3];
            }
            if(i % 8 == 0){
                {
                    // 循环左移
                    byte u8tmp = tempa[0];
                    tempa[0] = tempa[1];
                    tempa[1] = tempa[2];
                    tempa[2] = tempa[3];
                    tempa[3] = u8tmp;
                }

                // SubWord() is a function that takes a four-byte input word and
                // applies the S-box to each of the four bytes to produce an output word.

                // Function Subword()
                {
                    tempa[0] = getSBoxValue(tempa[0]);
                    tempa[1] = getSBoxValue(tempa[1]);
                    tempa[2] = getSBoxValue(tempa[2]);
                    tempa[3] = getSBoxValue(tempa[3]);
                }

                tempa[0] = (byte) (tempa[0] ^ Rcon[i/8]);

            }
            if(i % 8 == 4){
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }
            // 最后一步
            j = i * 4; k=(i - 8) * 4;
            RoundKey[j + 0] = (byte) (RoundKey[k + 0] ^ tempa[0]);
            RoundKey[j + 1] = (byte) (RoundKey[k + 1] ^ tempa[1]);
            RoundKey[j + 2] = (byte) (RoundKey[k + 2] ^ tempa[2]);
            RoundKey[j + 3] = (byte) (RoundKey[k + 3] ^ tempa[3]);
        }

        return RoundKey;
    };


    private boolean byteArrayAllZero(byte[] array) {
        int sum = 0;
        for (byte b : array) {
            sum |= b;
        }
        return (sum == 0);
    }

    // 输入32个字节,快速筛选”不是AES-128 Key“,目前可以筛选99%的内存块
    public boolean isAes128KeyFastJudge(byte[] InputArray){
        for(int i = 20; i < 32; i++){
            if(InputArray[i] != (InputArray[i - 4] ^ InputArray[i - 16])){
                return false;
            }
        }
        return true;
    }

    // 输入64个字节,快速筛选”不是AES-256 Key“,目前可以筛选99%的内存块
    public boolean isAes256KeyFastJudge(byte[] InputArray){
        for(int i = 36; i < 48; i++){
            if(InputArray[i] != (InputArray[i - 4] ^ InputArray[i - 32])){
                return false;
            }
        }
        for(int i = 52; i < 64; i++){
            if(InputArray[i] != (InputArray[i - 4] ^ InputArray[i - 32])){
                return false;
            }
        }
        return true;
    }



    public byte[] ConvertToLittleEdian(byte[] InputArray){
        byte[] LittleEdianKey = new byte[InputArray.length];
        for(int i = 0; i < (InputArray.length / 4) ; i ++){
            LittleEdianKey[(i * 4) + 0] = InputArray[(i + 1) * 4 - 1];
            LittleEdianKey[(i * 4) + 1] = InputArray[(i + 1) * 4 - 2];
            LittleEdianKey[(i * 4) + 2] = InputArray[(i + 1) * 4 - 3];
            LittleEdianKey[(i * 4) + 3] = InputArray[(i + 1) * 4 - 4];
        }
        return LittleEdianKey;
    }


    // 判断传入的176个元素的字节数组是否是标准/非标准的AES-128 Key
    // 0 即不是Key， 1 即大端序的Key，2 是大端序的魔改Key，3是小端序的标准Key，4是小端序的魔改Key
    public int IsAes128Key(byte[] InputArray){
        byte[] KeyExpandedBig = ExpandKey128BigEdian(InputArray);
        if(arrayEquals(KeyExpandedBig, InputArray) > 0){
            return 1;
        }else if(arrayEquals(ConvertToLittleEdian(ExpandKey128BigEdian(ConvertToLittleEdian(InputArray))), InputArray)>0){
            return 3;
        }else {
            return 0;
        }

    };


    // 判断传入的240个元素的字节数组是否是标准/非标准的AES-256 Key
    // 0 即不是Key， 1 即大端序的Key，2 是大端序的魔改Key，3是小端序的标准Key，4是小端序的魔改Key
    public int IsAes256Key(byte[] InputArray){
        byte[] KeyExpandedBig = ExpandKey256BigEdian(InputArray);
        if(arrayEquals(KeyExpandedBig, InputArray) > 0){
            return 1;
        }else if(arrayEquals(ConvertToLittleEdian(ExpandKey256BigEdian(ConvertToLittleEdian(InputArray))), InputArray)>0){
            return 3;
        }else {
            return 0;
        }

    };

    private int searchMemory(long start, long end) {
        int exist = 0;
        MemoryRegion = backend.mem_read(start, end - start);
        for (long i = start; i <= end - (11 * 16); i = i+4) {
            // 去除一些潜在的空内存块
            byte[] oneBlock = Arrays.copyOfRange(MemoryRegion, (int)(i - start) , (int)(i - start + 0x10));
            if(byteArrayAllZero(oneBlock)){
                i = i + 0x10 - 4;
            }
            else if(isAes128KeyFastJudge(Arrays.copyOfRange(MemoryRegion, (int)(i - start) , (int)(i - start + 0x20)))){
                byte[] BigBlock = Arrays.copyOfRange(MemoryRegion, (int)(i - start) , (int)(i - start + (11 * 16)));
                if(containsSubArray(keylist, BigBlock)){
                    i = i + (11 * 16) - 4;
                    continue;
                }
                int result = IsAes128Key(BigBlock);
                if(result>0){
                    exist++;
                    System.out.println("AES 128 Key Address:0x"+Integer.toHexString((int) i));
                    keylist.add(BigBlock);
                    keylist = new ArrayList<>(new HashSet<>(keylist));
                    if(result == 1){
                        Inspector.inspect(oneBlock, "AES-128 Key(BigEdian)");
                    }else if(result == 3){
                        Inspector.inspect(ConvertToLittleEdian(oneBlock), "AES-128 Key(LittleEdian)");
                    }
                }
            }
        }
        for (long i = start; i <= end - (15 * 16); i = i+4) {
            // 去除一些潜在的空内存块
            byte[] oneBlock = Arrays.copyOfRange(MemoryRegion, (int)(i - start) , (int)(i - start + 0x20));
            if(byteArrayAllZero(oneBlock)){
                i = i + 0x20 - 4;
            }
            else if(isAes256KeyFastJudge(Arrays.copyOfRange(MemoryRegion, (int)(i - start) , (int)(i - start + 0x40)))){
                byte[] BigBlock = Arrays.copyOfRange(MemoryRegion, (int)(i - start) , (int)(i - start + (15 * 16)));
                if(containsSubArray(keylist, BigBlock)){
                    i = i + (15 * 16) - 4;
                    continue;
                }
                int result = IsAes256Key(BigBlock);
                if(result>0){
                    exist++;
                    System.out.println("AES 256 Key Address:0x"+Integer.toHexString((int) i));
                    keylist.add(BigBlock);
                    keylist = new ArrayList<>(new HashSet<>(keylist));
                    if(result == 1){
                        Inspector.inspect(oneBlock, "AES-256 Key(BigEdian)");
                    }else if(result == 3){
                        Inspector.inspect(ConvertToLittleEdian(oneBlock), "AES-256 Key(LittleEdian)");
                    }
                }
            }
        }
        return exist;
    }


    public void searchEveryFunction(final long start, final List<String> funcList){
        System.out.println("Searching AES Key Start...");
        for(String fun : funcList){
            final long addr = Long.parseLong(fun.split("!")[0], 16);
            emulator.attach().addBreakPoint(start + addr, new BreakPointCallback() {
                int count = 0;
                @Override
                public boolean onHit(Emulator<?> emulator, long address) {
                    count ++;
                    if(count > 8){
//                        System.out.println("工具函数，去除其函数断点");
                        backend.removeBreakPoint(start + addr);
                        return true;
                    }
                    final long returnAddress = emulator.getContext().getLRPointer().peer;
                    if(!breakTrace.contains(returnAddress)){
                        breakTrace.add(returnAddress);
                        emulator.attach().addBreakPoint(returnAddress, new BreakPointCallback() {
                            @Override
                            public boolean onHit(Emulator<?> emulator, long address) {
                                if(count > 8){
//                                    System.out.println("工具函数，去除其函数返回处断点");
                                    backend.removeBreakPoint(returnAddress);
                                    return true;
                                }else {
                                    if(searchKeyInMemory()){
                                        System.out.println("Generate At Function : 0x"+ Integer.toHexString((int) (address-start)));
                                        System.out.println(">-----------------------------------------------------------------------------<\n");
                                    }
                                    return true;
                                }
                            }
                        });
                    }

                    return true;
                }
            });

        }
    }

    public static List<String> readFuncFromIDA(String path){
        List<String> funcList = new ArrayList<>();
        try {
            // open file to read
            Scanner scanner = new Scanner(new File(path));

            // read until end of file (EOF)
            while (scanner.hasNextLine()) {
                String oneLine = scanner.nextLine().replaceAll("\t", "").replaceAll("0x", "");
                funcList.add(oneLine);
            }

            // close the scanner
            scanner.close();

        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        }
        return funcList;
    }

}
