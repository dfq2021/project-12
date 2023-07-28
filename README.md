# project-12
verify the above pitfalls with proof-of-concept code
# 问题重述
![Cache_-30b4e624161496d6](https://github.com/jlwdfq/project-12/assets/129512207/9d6bcb2e-c8bb-43a3-ba81-292266412535)
本次实验中共验证的内容有

1.泄露随机数k从而导致d泄露。

2.对不同的消息重用随机数k从而导致d泄露。

3.两个不同的用户使用同一个k，则其中一个人可以推出另一个人的私钥d。

4.可以(r,s) and (r,-s)均为有效签名，这可能会导致区块网络分裂。

5.使用相同的d和随机数k签发SM2和ECDSA或Schnorr和ECDSA，会导致d泄露。
# 实验准备
### ECDSA
算法描述：
![image](https://github.com/jlwdfq/project-12/assets/129512207/3d09190c-f927-451a-b9e3-1f1997ba6148)

关键代码：
```python
def ECDSA_sign(m, sk):
    while 1:
        k = secrets.randbelow(N)  # N is prime, then k <- Zn*
        R = EC_multi(k, G)
        r = R[0] % N  # Rx mod n
        if r != 0:
            break
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    tmp1 = inv(k, N)
    tmp2 = (e + sk * r) % N
    s = tmp1 * tmp2 % N
    return (r, s)


def ECDSA_verify(signature, m, pk):
    r, s = signature
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    w = inv(s, N)
    tmp1 = EC_multi(e * w, G)
    tmp2 = EC_multi(r * w, pk)
    dot = EC_add(tmp1, tmp2)
    x = dot[0]
    return x == r


```
### SM2
算法描述：
![image](https://github.com/jlwdfq/project-12/assets/129512207/b6ce5a29-3711-45c1-abdb-6e031ff4b565)


```python
# SM2签名
def sm2_sign(sk, msg, ZA):
    """SM2 signature algorithm"""
    gangM = ZA + msg
    gangM_b = bytes(gangM, encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(gangM_b))
    e = int(e, 16)  # str -> int
    while 1:
        k = secrets.randbelow(N)  # generate random number k
        a_dot = EC_multi(k, G)  # (x1, y1) = kG
        r = (e + a_dot[0]) % N  # r = (e + x1) % n
        s = 0
        if r != 0 and r + k != N:
            s = (inv(1 + sk, N) * (k - r * sk)) % N
        if s != 0:  return (r, s)


# SM2验签
def sm2_verify(pk, ID, msg, signature):
    """SM2 verify algorithm
    :param pk: public key
    :param ID: ID
    :param msg: massage
    :param signature: (r, s)
    :return: true/false
    """
    r = signature[0]  # r'
    s = signature[1]  # s'
    ZA = precompute(ID, A, B, G_X, G_Y, pk[0], pk[1])
    gangM = str(ZA) + msg
    gangM_b = bytes(gangM, encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(gangM_b))  # e'
    e = int(e, 16)  # str -> int
    t = (r + s) % N

    dot1 = EC_multi(s, G)
    dot2 = EC_multi(t, pk)
    dot = EC_add(dot1, dot2)  # (x2, y2) = s'G + t'pk

    R = (e + dot[0]) % N  # R = (e' + x2) % N
    return R == r
```
### Schnorr
算法描述：
![VR_SD$~W4(L`_I$HGU~K`D5](https://github.com/jlwdfq/project-12/assets/129512207/7bc1b8e0-154e-4c28-b3b1-53bf87b402b9)

关键代码：
```python
# Schnorr签名
def Schnorr_sign(M, sk):
    k = secrets.randbelow(N)
    R = EC_multi(k, G)
    tmp = str(R[0]) + str(R[1]) + M
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    s = k + e * sk % N
    return R, s

# Schnorr验签
def Schnorr_verify(signature, M, pk):
    R, s = signature
    tmp = str(R[0]) + str(R[1]) + M
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    tmp1 = EC_multi(s, G)
    tmp2 = EC_multi(e, pk)
    tmp2 = EC_add(R, tmp2)
    return tmp1 == tmp2
```
# 实现思路
### 1.泄露随机数k从而导致d泄露
![image](https://github.com/jlwdfq/project-12/assets/129512207/c8cf5e74-d49b-4cf0-8ce7-aa331cb3cfc7)

下面以SM2为例，展示关键代码：
```python
def sm2_leaking_k():
    """
    A:KeyGen-->(sk_a,pk_a)
       Sign-->Sig_ska(msg)
    """
    ID = 'A'
    msg = "dfq202100460092"
    sk_a, pk_a = key_gen()
    k = secrets.randbelow(N)  # 泄露的k
    ZA = precompute(ID, A, B, G_X, G_Y, pk_a[0], pk_a[1])
    Sign = sm2_sign_and_assign_k(k, sk_a, msg, str(ZA))
    r, s = Sign
    print("sk_a \t\t\t A的私钥 \t\t", '0x' + hex(sk_a)[2:].rjust(64, '0'))
    print("message from A:\t\t\t", msg)
    print("Sign_ska_msg\t即用A的秘钥sk_a对上述消息生成的签名：", Sign)

    """
    B:deduce sk_a from k,Sign
      deduce result: d = (k - s) / (s + r)
    """
    d = (k - s) * inv(s + r, N) % N
    print("B推导出的 sk_a为：\t\t", '0x' + hex(d)[2:].rjust(64, '0'))
    if d == sk_a:
        print("d=sk_a, B 推导出正确的 sk_a!!!")
    else:
        print("B推导失败 d错误")

    """
    B: forge Sign using deduced sk_a(d)
       forge result: Sign_f
       Verify Sign_f using pk_a
    """
    # msg_f是B签名的消息
    msg_f = "dfq202100460092fromB"
    print("B传来的消息内容：\t", msg_f)
    pk_f = EC_multi(d, G)  # d对应的公钥
    ZA_f = precompute(ID, A, B, G_X, G_Y, pk_f[0], pk_f[1])
    Sign_f = sm2_sign(d, msg_f, str(ZA_f))
    print("B用推导出的私钥sk_a得到的签名：\t", Sign_f)
    print("B 将该签名用A的公钥验证...")
    if sm2_verify(pk_a, ID, msg_f, Sign_f) == 1:
        print("通过...伪造成功!")
    else:
        print("失败...伪造未成功")

```
### 2.对不同的消息重用随机数k从而导致d泄露
传入参数r1,s1,r2,s2(使用同一个k进行签名)，则d的计算式为：

d1=s2-s1

d2=s1-s2+r1-r2

d=(d1/d2) mod n

如图：
![image](https://github.com/jlwdfq/project-12/assets/129512207/04b8178e-8052-4ed7-a596-5ab1ddf3a6fb)

下面以Schnorr为例，展示关键代码：
```python
def Schnorr_reusing_k():
    sk, pk = key_gen()
    print("sk_A \t\t\tA的秘钥\t\t", '0x' + hex(sk)[2:].rjust(64, '0'))
    msg1 = "DFQ"
    msg2 = "dfq"
    k = secrets.randbelow(N)  # 相同的k值
    signature1 = Schnorr_sign_and_assign_k(k, msg1, sk)
    signature2 = Schnorr_sign_and_assign_k(k, msg2, sk)
    R1, s1 = signature1
    R2, s2 = signature2
    if R1 != R2: return 'error'
    R = R1
    tmp = str(R[0]) + str(R[1]) + msg1
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    tmp = str(R[0]) + str(R[1]) + msg2
    e2 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d = ((s1 - s2) % N) * inv((e1 - e2), N) % N
    print("d \t\t\t\t((B 通过分析推导出的 sk_a))\t\t", '0x' + hex(d)[2:].rjust(64, '0'))
    if d == sk:
        print("d==sk_a, B 成功推导出真正的sk_A!!!")
    else:
        print("B 推导失败，d！=sk_a")
    msg_f = "20000460092"
    Sign_f = Schnorr_sign(msg_f, d)
    print("B通过A的公钥验证...")
    if Schnorr_verify(Sign_f, msg_f, pk) == 1:
        print("验证成功...成功伪造!")
    else:
        print("验证失败...伪造未成功")
```
### 3.两个不同的用户使用同一个k，则其中一个人可以推出另一个人的私钥d

![image](https://github.com/jlwdfq/project-12/assets/129512207/79b6e459-dec4-4ef0-9723-289261333055)

如图，AB两个不同的人使用同一个k，则其中一个人可以推出另一个人的d.

假设A使用k签发了(r1,s1),B使用k签发了(r2,s2)，则两者对应的d分别为：

dB=((k-s2)/(s2+r2)) mod n

dA=((k-s1)/(s1+r1)) mod n

下面以SM2为例，展示关键代码：
```python
def same_k_of_different_users():
    # A1和A2使用相同的k签名
    k = secrets.randbelow(N)  # 相同的k值
    sk_a1, pk_a1 = key_gen()
    msg_a1 = "message from A1"
    ID_a1 = 'A1'
    ZA1 = precompute(ID_a1, A, B, G_X, G_Y, pk_a1[0], pk_a1[1])
    Sign1 = sm2_sign_and_assign_k(k, sk_a1, msg_a1, str(ZA1))
    print(" A1的私钥sk_a1为：\t\t", '0x' + hex(sk_a1)[2:].rjust(64, '0'))

    r1, s1 = Sign1
    d1 = (k - s1) * inv(s1 + r1, N) % N
    print("A2推导的sk_a1为：\t\t", '0x' + hex(d1)[2:].rjust(64, '0'))
    if d1 == sk_a1:
        print("推导结果=sk_a1,A2推导出正确的sk_a1!!!")
    else:
        print("推导结果！=sk_a1，A2未能推导出正确的sk_a1")

    sk_a2, pk_a2 = key_gen()
    msg_a2 = "message from A2"
    ID_a2 = 'A2'
    ZA2 = precompute(ID_a2, A, B, G_X, G_Y, pk_a2[0], pk_a2[1])
    Sign2 = sm2_sign_and_assign_k(k, sk_a2, msg_a2, str(ZA2))
    print("A2的私钥sk_a2为：\t\t", '0x' + hex(sk_a2)[2:].rjust(64, '0'))
    r2, s2 = Sign2
    d2 = (k - s2) * inv(s2 + r2, N) % N
    print("A1 推导出的 sk_a2为：\t\t", '0x' + hex(d2)[2:].rjust(64, '0'))
    if d2 == sk_a2:
        print("推导正确, A1推导出A2的私钥sk_a2!!!")
    else:
        print("A1 未能推导出正确的 sk_a2")
```
### 4.可以(r,s) and (r,-s)均为有效签名
通过验证算法分别验证(r,s)和 (r,-s)，并查看结果。

以ECDSA为例，关键代码如下：
```python
def verify_Malleability():
    # Alice生成消息签名
    sk, pk = key_gen()
    message = "dfq202100460092"
    signature = ECDSA_sign(message, sk)
    r, s = signature
    signature_test = (r, -s)
    print("信息",message,"生成的签名r，s为：",r,s)
    print(" 验证 (r,-s)...")
    if ECDSA_verify(signature_test, message, pk) == 1:
        print("验证通过!")
    else:
        print("验证失败!")
```
### 5.使用相同的d和随机数k签发SM2和ECDSA或Schnorr和ECDSA，会导致d泄露。
![image](https://github.com/jlwdfq/project-12/assets/129512207/32e76aa4-cd08-4c36-afa9-ab9e18e9117c)

下面以Schnorr和ECDSA为例，展示关键代码：
```python
def same_dk_of_ECDSA_Schnorr():
    # same d and k
    sk, pk = key_gen()
    print("相同的 sk\t\t\t", "0x" + hex(sk)[2:].rjust(64, '0'))
    k = secrets.randbelow(N)
    # ECDSA签名(1)
    message1 = "ECSDA"
    signature1 = ECDSA_sign_and_assign_k(k, message1, sk)
    # Schnorr签名(2)
    message2 = "Schnorr"
    signature2 = Schnorr_sign_and_assign_k(k, message2, sk)
    r, s1 = signature1
    R, s2 = signature2
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(message1, encoding='utf-8'))), 16)
    tmp = str(R[0]) + str(R[1]) + message2
    e2 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    tmp1 = (s2 - inv(s1, N) * e1) % N
    tmp2 = (inv(s1, N) * r + e2) % N
    d = tmp1 * inv(tmp2, N) % N
    print("推导得到的私钥sk'为  ", '0x' + hex(d)[2:].rjust(64, '0'))
    if d == sk:
        print("d==sk, 推导出真正的sk私钥!!!")
    else:
        print("推导失败")

```
# 实验结果
按照实验要求，本次实验的五种pitfalls在1.ECDSA、2.SM2、3.Schnorr三种算法体系中均得到了验证，由于篇幅关系，便不再一一展示。下图为各个算法的pitfalls验证结果
### 1.ECDSA
![image](https://github.com/jlwdfq/project-12/assets/129512207/1140f40a-a313-4a77-abd0-f0201f32f44e)
### 2.SM2
![image](https://github.com/jlwdfq/project-12/assets/129512207/5e64507b-c9f4-4c0e-861d-bd0b6f237754)
### 3.Schnorr
![image](https://github.com/jlwdfq/project-12/assets/129512207/7fee2483-ad48-42d6-ae4f-6c37f33b2556)

# 实验环境
| 语言  | 系统      | 平台   | 处理器                     |
|-------|-----------|--------|----------------------------|
| Cpp   | Windows10 | pycharm| Intel(R) Core(TM)i7-11800H |
# 小组分工
戴方奇 202100460092 单人组完成project12
