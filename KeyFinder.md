### KeyFinder 食用指南

KeyFinder 是一个Unidbg的插件，通过内存检索的方式查找AES的密钥，用于增强Unidbg分析和还原算法的能力。



### 使用方法

三步骤

1.将functionList.py放到IDA插件列表，IDA即可使用getFunctions插件，运行并在SO文件目录生成txt文件（目前仅测试过IDA 7.5哦）

2.确保Unidbg已经能正常跑出函数结果

3.在一个尽早的时机开启AesKeyFinder，详见instance1.java 示例代码文件。



### 注意事项

- 加固SO需要脱壳修复后才能使用functionList

- 正常样本一般运行数秒到数分钟

  

### TODO

- 支持AES-192
- 支持部分魔改的AES密钥扩展函数
- 支持DES/RSA/SM4 等加密算法

