#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import datetime
import os
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms


def signature_appearance(input_pdf_path, cert_path, cert_password, sign_img):
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "auto_sigfield": True,
        #"sigandcertify": False,
        "signaturebox": (72, 396, 360, 468),
        "signform": False,
        "sigfield": "Signature",

        # Text will be in the default font
        # Fields in the list display will be included in the text listing
        # Icon and background can both be set to images by having their
        #   value be a path to a file or a PIL Image object
        # If background is a list it is considered to be an opaque RGB colour
        # Outline is the colour used to draw both the border and the text
        "signature_appearance": {
            'background': [0.75, 0.8, 0.95],
            'icon': f'{sign_img}',
            'outline': [0.2, 0.3, 0.5],
            'border': 2,
            'labels': True,
            'display': 'CN,DN,date,contact,reason,location'.split(','),
            },

        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
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
