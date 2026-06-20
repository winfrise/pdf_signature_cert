import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ==========================================
# 1. 基础工具函数：生成密钥
# ==========================================
def generate_rsa_key(key_size=2048):
    """生成一个新的 RSA 私钥"""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

# ==========================================
# 2. 核心业务函数：签发证书
# ==========================================
def sign_certificate(subject_name, issuer_name, issuer_key, subject_key, is_ca=False, days_valid=365):
    """
    通用的证书签发函数
    :param subject_name: 证书持有者信息 (x509.Name)
    :param issuer_name: 颁发者信息 (x509.Name)
    :param issuer_key: 颁发者的私钥 (用于签名)
    :param subject_key: 证书持有者的公钥 (嵌入到证书中)
    :param is_ca: 是否是 CA 证书
    :param days_valid: 有效期天数
    :return: 签好的证书对象
    """
    now = datetime.now(timezone.utc)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(subject_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=days_valid))

    # 如果是 CA 证书，添加基本约束扩展
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    else:
        # 如果是用户证书，添加用途扩展 (PDF签名/邮件保护等)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                x509.ExtendedKeyUsageOID.CODE_SIGNING # 包含文档签名
            ]),
            critical=False,
        )

    # 执行签名动作
    certificate = builder.sign(
        private_key=issuer_key,
        algorithm=hashes.SHA256(),
    )
    return certificate

# ==========================================
# 3. 辅助函数：保存文件
# ==========================================
def save_pem(file_path, data):
    """将 PEM 格式的数据保存到文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(data)
    print(f"[成功] 已保存文件: {file_path}")

# ==========================================
# 4. 主执行流程 (Main Execution Flow)
# ==========================================
def main():
    print("--- 开始构建证书体系 ---")

    # 【第一步】生成根 CA 的密钥和自签名证书
    root_key = generate_rsa_key()
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"AA TriSoft Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TriSoft"),
    ])
    # 根证书是自己签自己 (Issuer == Subject)
    root_cert = sign_certificate(
        subject_name=root_name,
        issuer_name=root_name,
        issuer_key=root_key,
        subject_key=root_key.public_key(),
        is_ca=True,
        days_valid=40*365 # 40年
    )
    print(">> 根 CA 生成完毕")

    # 【第二步】生成中间 CA 的密钥，并由根 CA 签发
    inter_key = generate_rsa_key()
    inter_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"AA TriSoft Intermediate CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TriSoft"),
    ])
    # 中间证书由根 CA 签发 (Issuer 是 Root)
    inter_cert = sign_certificate(
        subject_name=inter_name,
        issuer_name=root_name, # 注意这里
        issuer_key=root_key,   # 注意这里
        subject_key=inter_key.public_key(),
        is_ca=True,
        days_valid=10*365
    )
    print(">> 中间 CA 生成完毕")

    # 【第三步】生成用户证书 (循环处理 demo1, demo2, demo3)
    users = ["demo1@trisoft.com.pl"]

    for email in users:
        # 3.1 生成用户密钥
        user_key = generate_rsa_key()

        # 3.2 准备用户身份信息
        user_name = x509.Name([
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
            x509.NameAttribute(NameOID.COMMON_NAME, email),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TriSoft User"),
        ])

        # 3.3 由中间 CA 签发用户证书
        user_cert = sign_certificate(
            subject_name=user_name,
            issuer_name=inter_name, # 颁发者是中间 CA
            issuer_key=inter_key,   # 使用中间 CA 的私钥
            subject_key=user_key.public_key(),
            is_ca=False, # 这不是 CA
            days_valid=365
        )

        # 3.4 保存文件 (模拟原脚本的文件结构)
        base_dir = "ca"
        prefix = email.split('@')[0]

        # 保存私钥
        save_pem(f"{base_dir}/{prefix}_private_key.pem", user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

        # 保存证书
        save_pem(f"{base_dir}/{prefix}_public_key.pem", user_cert.public_bytes(serialization.Encoding.PEM))

        # 保存 P12 (PKCS12) - 方便导入浏览器或 Adobe
        from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
        p12_data = serialize_key_and_certificates(
            name=b"My Certificate",
            key=user_key,
            cert=user_cert,
            cas=[inter_cert, root_cert], # 包含完整的信任链
            encryption_algorithm=serialization.NoEncryption()
        )
        save_pem(f"{base_dir}/{prefix}_cert_bundle.p12", p12_data)

    print("\n--- 全部完成！请在 'ca' 文件夹中查看生成的文件 ---")

# 启动程序
if __name__ == "__main__":
    main()