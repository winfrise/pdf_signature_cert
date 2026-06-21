#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import datetime
import os
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms


def signature_appearance(input_pdf_path, cert_path, cert_password, sign_img):
    date = datetime.datetime.utcnow()
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 0,
        "sigflags": 3,  
        "sigflagsft": 132,
        "sigpage": 0,  # 指定签名显示在哪一页。0 代表 第一页。
        "auto_sigfield": True,  # 自动创建签名字段。
        "sigandcertify": True,
        "signform": False,
        "sigfield": "Signature",  # 签名字段的名称
        "signingdate": date,
        "reason": "电子合同签名",
        "password": "1234",
    }
    with open(cert_path, "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(),  
            f"{cert_password}".encode('utf-8'), 
            backends.default_backend()
        )
    

    datau = open(input_pdf_path, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    output_pdf_path = input_pdf_path.replace(".pdf", "-signature_appearance.pdf")
    with open(output_pdf_path, "wb") as fp:
        fp.write(datau)
        fp.write(datas)

    print("--------------签名完成--------------")

if __name__ == "__main__":
    BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../')

    input_pdf_path = f"{BASE_DIR}/pdf/test.pdf"
    cert_path=f"{BASE_DIR}/cert_auth/zfb_cert_bundle.p12"
    cert_password = "123456"
    sign_img = f"{BASE_DIR}/assets/images/signature_liudehua.png"

    signature_appearance(
        input_pdf_path = input_pdf_path,
        cert_path = cert_path,
        cert_password = cert_password,
        sign_img=sign_img
    )
