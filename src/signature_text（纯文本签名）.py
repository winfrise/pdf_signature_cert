#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import os
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms



def signature_text(input_pdf_path, cert_path, cert_password, sign_img):
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        #"auto_sigfield": False,
        #"sigandcertify": False,
        #"signaturebox": (0, 0, 590, 155),
        
        "signaturebox": (72, 396, 360, 468),
        "signform": False,

        # "signform": True,
        # "sigfield": "Signature",
        #             Text will be in the default font
        "signature": 'Signed field!',

        # default configuration for the text appearance
        "text": {
            'wraptext': True,
            'fontsize': 12,
            'textalign': 'left',
            'linespacing': 1.2,
            },

        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }
    with open(f"{cert_path}", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), 
            f"{cert_password}".encode('utf-8'), 
            backends.default_backend()
        )
    datau = open(input_pdf_path, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    output_pdf_path = input_pdf_path.replace(".pdf", "-signature_text.pdf")
    with open(output_pdf_path, "wb") as fp:
        fp.write(datau)
        fp.write(datas)

    print("--------------签名完成--------------")


if __name__ == "__main__":
    BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../')

    input_pdf_path = f"{BASE_DIR}/pdf/test.pdf"
    cert_path=f"{BASE_DIR}/cert_auth/demo1_cert_bundle.p12"
    cert_password = "123456"
    sign_img = f"{BASE_DIR}/assets/images/signature_liudehua.png"

    signature_text(
        input_pdf_path = input_pdf_path,
        cert_path = cert_path,
        cert_password = cert_password,
        sign_img=sign_img
    )

