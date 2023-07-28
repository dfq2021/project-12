# project-12
verify the above pitfalls with proof-of-concept code
# 问题重述
![Cache_-30b4e624161496d6](https://github.com/jlwdfq/project-12/assets/129512207/9d6bcb2e-c8bb-43a3-ba81-292266412535)
本次实验中共验证的内容由
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
# 实现方式
### 1.泄露随机数k从而导致d泄露
![image](https://github.com/jlwdfq/project-12/assets/129512207/c8cf5e74-d49b-4cf0-8ce7-aa331cb3cfc7)
### 2.对不同的消息重用随机数k从而导致d泄露
传入参数r1,s1,r2,s2(使用同一个k进行签名)，则d的计算式为：

d1=s2-s1

d2=s1-s2+r1-r2

d=(d1/d2) mod n
如图：
![image](https://github.com/jlwdfq/project-12/assets/129512207/04b8178e-8052-4ed7-a596-5ab1ddf3a6fb)

### 3.两个不同的用户使用同一个k，则其中一个人可以推出另一个人的私钥d

![image](https://github.com/jlwdfq/project-12/assets/129512207/79b6e459-dec4-4ef0-9723-289261333055)

如图，AB两个不同的人使用同一个k，则其中一个人可以推出另一个人的d.

假设A使用k签发了(r1,s1),B使用k签发了(r2,s2)，则两者对应的d分别为：

dB=((k-s2)/(s2+r2)) mod n

dA=((k-s1)/(s1+r1)) mod n
### 4.可以(r,s) and (r,-s)均为有效签名


### 5.使用相同的d和随机数k签发SM2和ECDSA或Schnorr和ECDSA，会导致d泄露。
![image](https://github.com/jlwdfq/project-12/assets/129512207/32e76aa4-cd08-4c36-afa9-ab9e18e9117c)
# 实验结果

# 实验环境
| 语言  | 系统      | 平台   | 处理器                     |
|-------|-----------|--------|----------------------------|
| Cpp   | Windows10 | pycharm| Intel(R) Core(TM)i7-11800H |
# 小组分工
戴方奇 202100460092 单人组完成project10
