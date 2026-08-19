import subprocess, sys, qrcode
from qrcode.util import QRData, MODE_8BIT_BYTE
from qrcode.exceptions import DataOverflowError
ECL = {0:qrcode.constants.ERROR_CORRECT_L,1:qrcode.constants.ERROR_CORRECT_M,
       2:qrcode.constants.ERROR_CORRECT_Q,3:qrcode.constants.ERROR_CORRECT_H}
def oracle(data, v, ecl, mask):
    qr = qrcode.QRCode(version=v, error_correction=ECL[ecl], mask_pattern=mask, border=0)
    qr.add_data(QRData(data.encode(), mode=MODE_8BIT_BYTE))
    qr.make(fit=False)
    return ["".join("1" if x else "0" for x in row) for row in qr.get_matrix()]
def mine(data, v, ecl, mask):
    out = subprocess.check_output(["/tmp/qrdump", data, str(v), str(ecl), str(mask)]).decode()
    return out.strip("\n").split("\n")
tests = ["http://192.168.1.5:8000/", "https://bandrop.local:8000/abc123",
         "hello", "x"*20, "BANDROP", "http://10.0.0.42:9090/d/token-9f2a/", "z"*100]
fails=0; total=0; skipped=0
for data in tests:
    for v in range(1,11):
        for ecl in range(4):
            for mask in range(8):
                try:
                    o=oracle(data,v,ecl,mask)
                except DataOverflowError:
                    skipped+=1; continue
                total+=1
                m=mine(data,v,ecl,mask)
                if o!=m:
                    fails+=1
                    if fails<=3:
                        print(f"MISMATCH data={data!r} v={v} ecl={ecl} mask={mask}")
                        for i,(a,b) in enumerate(zip(o,m)):
                            if a!=b: print(f"  row{i}\n  O {a}\n  M {b}"); break
print(f"\n{total-fails}/{total} matched ({skipped} combos didn't fit, skipped), {fails} failures")
sys.exit(1 if fails else 0)
