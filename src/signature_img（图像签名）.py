#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import os
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms

# from endesive.pdf import cmsn as cms

# import logging
# logging.basicConfig(level=logging.DEBUG)


def signature_img(input_pdf_path, cert_path, cert_password, sign_img):
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
        "signform": True,
        "sigfield": "Signature",
        #                PIL Image object or path to image file
        #                Image will be resized to fit bounding box
        "signature_img": f'{sign_img}',
        "signature_img_distort": False, # default True
        "signature_img_centred": False, # default True

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
    output_pdf_path = input_pdf_path.replace(".pdf", "-signature_img.pdf")
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

    signature_img(
        input_pdf_path = input_pdf_path,
        cert_path = cert_path,
        cert_password = cert_password,
        sign_img=sign_img
    )
