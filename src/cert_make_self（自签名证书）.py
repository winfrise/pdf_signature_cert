import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
# 移除了 from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
# 因为我们会稍后以不同方式调用它，或者保持原样也可以。

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
def main(cert_password):
    print("--- 开始构建单层自签名证书体系 ---")

    # 【修改点1】：移除了生成根CA和中间CA的代码

    # 【修改点2】：生成用户证书 (循环处理 demo1, demo2, demo3)
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

        # 3.3 【核心修改】由用户自己签发用户证书 (自签名)
        # 注意：subject_name 和 issuer_name 是同一个对象
        # 注意：签名使用的 issuer_key 是用户自己的私钥 user_key
        user_cert = sign_certificate(
            subject_name=user_name,
            issuer_name=user_name,  # 颁发者就是自己
            issuer_key=user_key,    # 用自己的私钥签名
            subject_key=user_key.public_key(),
            is_ca=False, # 这不是 CA
            days_valid=365
        )

        # 3.4 保存文件
        base_dir = "cert_auth"
        prefix = email.split('@')[0]

        # 保存私钥
        save_pem(f"{base_dir}/{prefix}_self_private_key.pem", user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

        # 保存证书
        save_pem(f"{base_dir}/{prefix}_self_public_key.pem", user_cert.public_bytes(serialization.Encoding.PEM))

        # 保存 P12 (PKCS12)
        # 【修改点3】：cas 参数设为 None 或空列表，因为不再有CA证书链
        from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
        p12_data = serialize_key_and_certificates(
            name=f"{email}".encode('utf-8'),
            key=user_key,
            cert=user_cert,
            cas=None,  # 不包含CA链
            encryption_algorithm=serialization.BestAvailableEncryption(f"{cert_password}".encode('utf-8'))
        )
        save_pem(f"{base_dir}/{prefix}_self_cert_bundle.p12", p12_data)

    print("\n--- 全部完成！请在 'cert_auth' 文件夹中查看生成的文件 ---")

# 启动程序
if __name__ == "__main__":
    cert_password = "123456"
    main(cert_password=cert_password)