
import secrets
from gmssl import sm3, func

# 定义椭圆曲线参数、基点和阶
A = 0
B = 7
G_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (G_X, G_Y)
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
h = 1

# 利用扩展欧几里得求逆
def inv(a, n):
    def ext_gcd(a, b, arr):
        if b == 0:
            arr[0] = 1
            arr[1] = 0
            return a
        g = ext_gcd(b, a % b, arr)
        t = arr[0]
        arr[0] = arr[1]
        arr[1] = t - int(a / b) * arr[1]
        return g

    arr = [0, 1, ]
    gcd = ext_gcd(a, n, arr)
    if gcd == 1:
        return (arr[0] % n + n) % n
    else:
        return -1

# 加法
def EC_add(p, q):
    # 0：无穷远点
    if p == 0 and q == 0:
        return 0  # 0 + 0 = 0
    elif p == 0:
        return q  # 0 + q = q
    elif q == 0:
        return p  # p + 0 = p
    else:
        if p[0] == q[0]:
            if (p[1] + q[1]) % P == 0:
                return 0
            elif p[1] == q[1]:
                return EC_double(p)
        elif p[0] > q[0]:
            tmp = p
            p = q
            q = tmp
        r = []
        slope = (q[1] - p[1]) * inv(q[0] - p[0], P) % P  # 斜率
        r.append((slope ** 2 - p[0] - q[0]) % P)
        r.append((slope * (p[0] - r[0]) - p[1]) % P)
        return r[0], r[1]

# 逆元
def EC_inv(p):
    r = [p[0], P - p[1]]
    return r


# 减法:p - q
def EC_sub(p, q):
    q_inv = EC_inv(q)
    return EC_add(p, q_inv)

# 自加:p+p
def EC_double(p):
    r = []
    slope = (3 * p[0] ** 2 + A) * inv(2 * p[1], P) % P
    r.append((slope ** 2 - 2 * p[0]) % P)
    r.append((slope * (p[0] - r[0]) - p[1]) % P)
    return r[0], r[1]

# 多倍点:ap
def EC_multi(a, p):
    n = p
    r = 0
    _bin = bin(a)[2:]
    _len = len(_bin)
    for i in reversed(range(_len)):
        if _bin[i] == '1':
            r = EC_add(r, n)
        n = EC_double(n)
    return r

# bit长度
def get_bit_num(x):
    if isinstance(x, int):  # when int
        num = 0
        tmp = x >> 64
        while tmp:
            num += 64
            tmp >>= 64
        tmp = x >> num >> 8
        while tmp:
            num += 8
            tmp >>= 8
        x >>= num
        while x:
            num += 1
            x >>= 1
        return num
    elif isinstance(x, str):  # when string
        return len(x.encode()) << 3
    elif isinstance(x, bytes):  # when bytes
        return len(x) << 3
    return 0


# 密钥生成
def key_gen():
    sk = int(secrets.token_hex(32), 16)
    pk = EC_multi(sk, G)
    return sk, pk

# 生成签名
def Schnorr_sign(M, sk):
    k = secrets.randbelow(N)
    R = EC_multi(k, G)
    tmp = str(R[0]) + str(R[1]) + M
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    s = k + e * sk % N
    return R, s

# 验证签名
def Schnorr_verify(signature, M, pk):
    R, s = signature
    tmp = str(R[0]) + str(R[1]) + M
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    tmp1 = EC_multi(s, G)
    tmp2 = EC_multi(e, pk)
    tmp2 = EC_add(R, tmp2)
    return tmp1 == tmp2


def Schnorr_sign_and_assign_k(k, M, sk):
    R = EC_multi(k, G)
    tmp = str(R[0]) + str(R[1]) + M
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    s = k + e * sk % N
    return (R, s)


def ECDSA_sign_and_assign_k(k, m, sk):
    R = EC_multi(k, G)
    r = R[0] % N  # Rx mod n
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    tmp1 = inv(k, N)
    tmp2 = (e + sk * r) % N
    s = tmp1 * tmp2 % N
    return (r, s)


# 【1】k泄露导致d泄露
def Schnorr_leaking_k():
    """
    A:KeyGen-->(sk_a,pk_a)
       Sign-->Sig_ska(msg)
    """
    sk, pk = key_gen()
    msg_a = "dfq202100460092fromA"
    k = secrets.randbelow(N)  # 该k为泄露的k
    signature = Schnorr_sign_and_assign_k(k, msg_a, sk)
    print("sk_A \t\t\t A的秘钥\t\t", '0x' + hex(sk)[2:].rjust(64, '0'))

    """
    B:deduce sk_a from msg,k,Sign
      deduce result: d = (s - k) / d mod N
    """
    R, s = signature
    tmp = str(R[0]) + str(R[1]) + msg_a
    e = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d = (s - k % N) * inv(e, N) % N
    print("d \t\t\t\t(B 通过分析推导出的 sk_a)\t\t", '0x' + hex(d)[2:].rjust(64, '0'))
    if d == sk:
        print("d==sk_a, B 成功推导出真正的sk_A")
    else:
        print("B 推导失败，d！=sk_a")

    """
       B: forge Sign using deduced sk_a(d)
          forge result: Sign_f
          Verify Sign_f using pk_a
    """
    msg_f = "dfq202100460092fromB"
    Sign_f = Schnorr_sign(msg_f, d)
    print("B通过A的公钥验证...")
    if Schnorr_verify(Sign_f, msg_f, pk) == 1:
        print("验证成功...成功伪造!")
    else:
        print("验证失败...伪造未成功")

# 【2】对不同的消息使用相同的k签名导致d泄露
def Schnorr_reusing_k():
    """
    A:KeyGen-->(sk_a,pk_a)
       Sign1-->Sig_ska(msg1)
       Sign2-->Sig_ska(msg2)
    """
    sk, pk = key_gen()
    print("sk_A \t\t\tA的秘钥\t\t", '0x' + hex(sk)[2:].rjust(64, '0'))
    msg1 = "DFQ"
    msg2 = "dfq"
    k = secrets.randbelow(N)  # 相同的k值
    signature1 = Schnorr_sign_and_assign_k(k, msg1, sk)
    signature2 = Schnorr_sign_and_assign_k(k, msg2, sk)

    '''
       B: deduce sk_a through msg1,msg2,Sign1,Sign2
          deduce result: d = (s1 - s2) / (e1 - e2)
    '''
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

    """
        B: forge Sign using deduced sk_a(d)
           forge result: Sign_f
           Verify Sign_f using pk_a
    """
    msg_f = "20000460092"
    Sign_f = Schnorr_sign(msg_f, d)
    print("B通过A的公钥验证...")
    if Schnorr_verify(Sign_f, msg_f, pk) == 1:
        print("验证成功...成功伪造!")
    else:
        print("验证失败...伪造未成功")


# 【3】两个不同的user使用相同的k,可以相互推测对方的私钥
def same_k_of_different_users():
    # A1和A2使用相同的k签名
    k = secrets.randbelow(N)  # 相同的k值
    """
            A1:KeyGen-->(sk_a1,pk_a1)
               Sign1-->Sig_ska1(msg1)
        """
    sk_a1, pk_a1 = key_gen()
    msg_a1 = "202100460092fromA1"
    Sign1 = Schnorr_sign_and_assign_k(k, msg_a1, sk_a1)
    print("sk_A1 \t\t\t A1的秘钥\t\t", '0x' + hex(sk_a1)[2:].rjust(64, '0'))

    '''
        A2: deduce sk_a1 through msg_a1,Sign1
            deduce result: d1  = (s - k) / d mod N
    '''
    r1, s1 = Sign1
    tmp = str(r1[0]) + str(r1[1]) + msg_a1
    e1 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d1 = (s1 - k % N) * inv(e1, N) % N
    print("d1 \t\t\t\t(A2  通过分析推导出的 sk_A1)\t\t", '0x' + hex(d1)[2:].rjust(64, '0'))
    if d1 == sk_a1:
        print("d1==sk_A1, A2 成功推导出真正的sk_A1!!!")
    else:
        print("A2推导失败，d1！=sk_A1")

    """
        A2:KeyGen-->(sk_a2,pk_a2)
           Sign1-->Sig_ska2(msg2)
    """
    sk_a2, pk_a2 = key_gen()
    msg_a2 = "202100460092fromA2"
    Sign2 = Schnorr_sign_and_assign_k(k, msg_a2, sk_a2)
    print("sk_A2 \t\t\t A2的秘钥\t\t", '0x' + hex(sk_a2)[2:].rjust(64, '0'))

    '''
        A1: deduce sk_a2 through msg_a2,Sign2
            deduce result: d2 = (s - k) / d mod N
    '''
    r2, s2 = Sign2
    tmp = str(r2[0]) + str(r2[1]) + msg_a2
    e2 = int(sm3.sm3_hash(func.bytes_to_list(bytes(tmp, encoding='utf-8'))), 16)
    d2 = (s2 - k % N) * inv(e2, N) % N
    print("d2 \t\t\t\t(A1 通过分析推导出的 sk_A2)\t\t", '0x' + hex(d2)[2:].rjust(64, '0'))
    if d2 == sk_a2:
        print("d2==sk_A2, A1成功推导出真正的sk_A2!!!")
    else:
        print("A1推导失败，d2！=sk_A2")


# 【4】验证(r,s) and (r,-s)均为合法签名
def verify_Malleability():
    # Alice生成消息签名
    sk, pk = key_gen()
    message = "dfq202100460092"
    signature = Schnorr_sign(message, sk)
    r, s = signature
    print("原有的签名r，s为：",r,s)
    signature_test = (r, -s)
    print("现在验证(r,-s)...")
    if Schnorr_verify(signature_test, message, pk) == 1:
        print("通过!")
    else:
        print("失败!")


#【5】 ECDSA与Schnorr使用相同的d和k而泄露d
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

    """
    deduce sk from msg1，msg2，Sign1，Sign2
    deduce result: d = (s2 - e1 / s1) / (r / s1 + e2)
    """

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


if __name__ == '__main__':
    print("===============================1.泄露随机数k从而导致d泄露=======================")
    Schnorr_leaking_k()
    print("")
    print("=======================2.对不同的消息重用随机数k从而导致d泄露======================")
    Schnorr_reusing_k()
    print("")
    print("==================3.两个不同的用户使用同一个k，则其中一个人可以推出另一个人的私钥d======")
    same_k_of_different_users()
    print("")
    print("=======================验证(r,s) and (r,-s)均为合法签名=========================")
    verify_Malleability()
    print("")
    print("========================使用相同的d和随机数k签发Schnorr和ECDSA，会导致私钥泄露=======")
    same_dk_of_ECDSA_Schnorr()
