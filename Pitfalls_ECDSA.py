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


def EC_add(p, q):
    # 0 means inf
    if p == 0 and q == 0:
        return 0  # 0 + 0 = 0
    elif p == 0:
        return q  # 0 + q = q
    elif q == 0:
        return p  # p + 0 = p
    else:
        if p[0] == q[0]:
            if (p[1] + q[1]) % P == 0:
                return 0  # mutually inverse
            elif p[1] == q[1]:
                return EC_double(p)
        elif p[0] > q[0]:  # swap if px > qx
            tmp = p
            p = q
            q = tmp
        r = []
        slope = (q[1] - p[1]) * inv(q[0] - p[0], P) % P  # 斜率
        r.append((slope ** 2 - p[0] - q[0]) % P)
        r.append((slope * (p[0] - r[0]) - p[1]) % P)
        return (r[0], r[1])


def EC_inv(p):
    r = [p[0]]
    r.append(P - p[1])
    return r


def EC_sub(p, q):
    q_inv = EC_inv(q)
    return EC_add(p, q_inv)


def EC_double(p):
    r = []
    slope = (3 * p[0] ** 2 + A) * inv(2 * p[1], P) % P
    r.append((slope ** 2 - 2 * p[0]) % P)
    r.append((slope * (p[0] - r[0]) - p[1]) % P)
    return (r[0], r[1])


def EC_multi(s, p):
    n = p
    r = 0
    s_bin = bin(s)[2:]
    s_len = len(s_bin)

    for i in reversed(range(s_len)):  # 类快速幂思想
        if s_bin[i] == '1':
            r = EC_add(r, n)
        n = EC_double(n)

    return r


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


def key_gen():
    sk = int(secrets.token_hex(32), 16)  # private key
    pk = EC_multi(sk, G)  # public key
    return sk, pk


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
def ECDSA_sign_and_return_k(m, sk):
    while 1:
        k = secrets.randbelow(N)  # N is prime, then k <- Zn*
        R = EC_multi(k, G)
        r = R[0] % N  # Rx mod n
        if r != 0: break
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    s = (inv(k, N) * (e + sk * r) % N) % N
    return (r, s), k


def ECDSA_sign_and_assign_k(m, k, sk):
    R = EC_multi(k, G)
    r = R[0] % N  # Rx mod n
    e = sm3.sm3_hash(func.bytes_to_list(bytes(m, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    tmp1 = inv(k, N)
    tmp2 = (e + sk * r) % N
    s = tmp1 * tmp2 % N
    return (r, s), k


# 【1】k泄露导致d泄露
def ECDSA_leaking_k():
    """
    A:KeyGen-->(sk_a,pk_a)
       Sign-->Sig_ska(msg)
    """
    sk, pk = key_gen()
    msg_a="DFQ202100460092"
    signature, k = ECDSA_sign_and_return_k(msg_a, sk)
    print("A的私钥sk_a：\t\t", '0x' + hex(sk)[2:].rjust(64, '0'))

    """
    B:deduce sk_a from msg,k,Sign
      deduce result: d =  (s * k - e) / r
    """
    r, s = signature
    e = sm3.sm3_hash(func.bytes_to_list(bytes(msg_a, encoding='utf-8')))  # e = hash(m)
    e = int(e, 16)
    d = (s * k - e) % N * inv(r, N) % N
    print("B推导的私钥sk_a‘为：\t\t", '0x' + hex(d)[2:].rjust(64, '0'))
    if d == sk:
        print("sk_a‘=sk_a, B 推导得到正确的 sk_a!!!")
    else:
        print("B 推导错误，与原sk_a不等")

    """
       B: forge Sign using deduced sk_a(d)
          forge result: Sign_f
          Verify Sign_f using pk_a
    """
    msg_f = "dfq202100460092"
    Sign_f = ECDSA_sign(msg_f, d)
    print("B（伪造者）将伪造的信息通过A的公钥验证..")
    if ECDSA_verify(Sign_f, msg_f, pk) == 1:
        print("验证通过...伪造成功!")
    else:
        print("验证失败...伪造未成功")


# 【2】对不同的消息使用相同的k签名导致d泄露
def ECDSA_reusing_k():
    """
    A:KeyGen-->(sk_a,pk_a)
       Sign1-->Sig_ska(msg1)
       Sign2-->Sig_ska(msg2)
    """
    sk, pk = key_gen()
    print("A的私钥sk_a 为：\t\t", '0x' + hex(sk)[2:].rjust(64, '0'))
    msg1 = "dfq"
    msg2 = "2021"
    signature1, k1 = ECDSA_sign_and_return_k(msg1, sk)
    signature2, k2 = ECDSA_sign_and_assign_k(msg2, k1, sk)

    '''
           B: deduce sk_a through msg1,msg2,Sign1,Sign2
              deduce result: d = [(s1 - s2) * k - (e1 - e2)] / (r1 - r2)
    '''

    r1, s1 = signature1
    r2, s2 = signature2
    r = r1
    e1 = sm3.sm3_hash(func.bytes_to_list(bytes(msg1, encoding='utf-8')))  # e = hash(m)
    e1 = int(e1, 16)
    e2 = sm3.sm3_hash(func.bytes_to_list(bytes(msg2, encoding='utf-8')))  # e = hash(m)
    e2 = int(e2, 16)
    d = (((e1 - e2) * s2) % N * inv((s1 - s2) % N, N) - e2) * inv(r, N) % N
    print("B 推导出的私钥 sk_a'为：\t\t", '0x' + hex(d)[2:].rjust(64, '0'))
    if d == sk:
        print("sk_a'=sk_a, B 推导出了正确的 sk_a!!!")
    else:
        print("sk_a'！=sk_a, B 未能推导出了正确的 sk_a")
    if k1 == k2:
        print("Sign1 Sign2 使用了相同的 k")
    else:
        print("Sign1 Sign2 没有使用相同的 k")

    """
        B: forge Sign using deduced sk_a(d)
           forge result: Sign_f
           Verify Sign_f using pk_a
    """
    msg_f = "20000460092"
    Sign_f = ECDSA_sign(msg_f, d)
    print("B 将仿造的信息用A的公钥pk_a验证...")
    if ECDSA_verify(Sign_f, msg_f, pk) == 1:
        print("验证通过...伪造成功!")
    else:
        print("验证失败...伪造未成功")


# 【3】两个不同的user使用相同的k,可以相互推测对方的私钥
def same_k_of_different_users():
    # A1和A2使用相同的k签名
    """
            A1:KeyGen-->(sk_a1,pk_a1)
               Sign1-->Sig_ska1(msg1)
    """
    sk_a1, pk_a1 = key_gen()
    msg_a1 = "message from A1"
    Sign1, k = ECDSA_sign_and_return_k(msg_a1, sk_a1)
    print("A1的私钥sk_a1 为：\t\t", '0x' + hex(sk_a1)[2:].rjust(64, '0'))

    '''
        A2: deduce sk_a1 through msg_a1,Sign1
            deduce result: d1 = (s * k - e) / r
    '''
    r1, s1 = Sign1
    e1 = sm3.sm3_hash(func.bytes_to_list(bytes(msg_a1, encoding='utf-8')))  # e = hash(m)
    e1 = int(e1, 16)
    d1 = (s1 * k - e1) % N * inv(r1, N) % N
    print("A2 推导的A1私钥 sk_a1'为：\t", '0x' + hex(d1)[2:].rjust(64, '0'))
    if d1 == sk_a1:
        print("sk_a1'=sk_a1, A2 推导出正确的 sk_a1!!!")
    else:
        print("sk_a1'！=sk_a1, A2 推导出正确的 sk_a1")

    """
        A2:KeyGen-->(sk_a2,pk_a2)
           Sign1-->Sig_ska2(msg2)
    """
    sk_a2, pk_a2 = key_gen()
    msg_a2 = "message from A2"
    Sign2,k = ECDSA_sign_and_return_k(msg_a2, sk_a2)
    print("A2的私钥sk_a2 wei：\t\t", '0x' + hex(sk_a2)[2:].rjust(64, '0'))

    '''
        A1: deduce sk_a2 through msg_a2,Sign2
            deduce result: = (s * k - e) / r
    '''
    r2, s2 = Sign2
    e2 = sm3.sm3_hash(func.bytes_to_list(bytes(msg_a2, encoding='utf-8')))  # e = hash(m)
    e2 = int(e2, 16)
    d2 = (s2 * k - e2) % N * inv(r2, N) % N
    print("A1推导出的私钥 sk_a2’为：)\t\t", '0x' + hex(d2)[2:].rjust(64, '0'))
    if d2 == sk_a2:
        print("sk_a2’=sk_a2, A1推导出正确的sk_a2!!!")
    else:
        print("sk_a2’！=sk_a2, A1未能推导出正确的sk_a2")

# 【4】验证(r,s) and (r,-s)均为合法签名
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


if __name__ == '__main__':
    print("===============================k泄露导致d泄露====================================")
    ECDSA_leaking_k()
    print("")
    print("=======================对不同的消息使用相同的k签名导致d泄露===========================")
    ECDSA_reusing_k()
    print("")
    print("==================两个不同的user使用相同的k,可以相互推测对方的私钥====================")
    same_k_of_different_users()
    print("")
    print("=======================验证(r,s) and (r,-s)均为合法签名=========================")
    verify_Malleability()